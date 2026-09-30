package javascript

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/cache"
	"github.com/anchore/syft/syft/pkg"
)

// useInMemoryCache installs a real (in-memory) cache manager for the duration of the test. By
// default syft's cache manager is bypassed, which is what keeps the rest of the cataloger tests
// isolated from one another; these tests need a functioning cache to observe caching behavior.
func useInMemoryCache(t *testing.T) {
	t.Helper()
	prev := cache.GetManager()
	cache.SetManager(cache.NewInMemory(time.Hour))
	t.Cleanup(func() { cache.SetManager(prev) })
}

// npmRegistryStub is a stand-in for registry.npmjs.org that counts the requests it serves.
type npmRegistryStub struct {
	*httptest.Server
	requests atomic.Int64
}

func newNpmRegistryStub(t *testing.T, handler http.HandlerFunc) *npmRegistryStub {
	t.Helper()
	stub := &npmRegistryStub{}
	stub.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stub.requests.Add(1)
		handler(w, r)
	}))
	t.Cleanup(stub.Close)
	return stub
}

func (s *npmRegistryStub) config() CatalogerConfig {
	return CatalogerConfig{SearchRemoteLicenses: true, NPMBaseURL: s.URL}
}

func TestJavascriptLicenseResolver_cachesSuccessfulLookups(t *testing.T) {
	useInMemoryCache(t)

	stub := newNpmRegistryStub(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"license": "MIT"}`)
	})

	lr := newJavascriptLicenseResolver(stub.config())

	for i := 0; i < 3; i++ {
		license, err := lr.getLicensesFromRemote("@babel/code-frame", "7.10.4")
		require.NoError(t, err)
		assert.Equal(t, "MIT", license)
	}

	assert.Equal(t, int64(1), stub.requests.Load(), "expected only the first lookup to reach the registry")
}

func TestJavascriptLicenseResolver_cacheIsSharedAcrossResolvers(t *testing.T) {
	useInMemoryCache(t)

	stub := newNpmRegistryStub(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"license": "MIT"}`)
	})

	// the same package/version is commonly present in more than one lockfile, each of which is
	// parsed by a different adapter with its own resolver -- the cache is still shared
	first := newJavascriptLicenseResolver(stub.config())
	second := newJavascriptLicenseResolver(stub.config())

	license, err := first.getLicensesFromRemote("lodash", "4.17.21")
	require.NoError(t, err)
	assert.Equal(t, "MIT", license)

	license, err = second.getLicensesFromRemote("lodash", "4.17.21")
	require.NoError(t, err)
	assert.Equal(t, "MIT", license)

	assert.Equal(t, int64(1), stub.requests.Load())
}

func TestJavascriptLicenseResolver_cachesEmptyLicense(t *testing.T) {
	useInMemoryCache(t)

	// a package that genuinely publishes no license field is a real answer, not a failure
	stub := newNpmRegistryStub(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"name": "no-license-pkg"}`)
	})

	lr := newJavascriptLicenseResolver(stub.config())

	for i := 0; i < 2; i++ {
		license, err := lr.getLicensesFromRemote("no-license-pkg", "1.0.0")
		require.NoError(t, err)
		assert.Equal(t, "", license)
	}

	assert.Equal(t, int64(1), stub.requests.Load())
}

func TestJavascriptLicenseResolver_doesNotCacheErrors(t *testing.T) {
	useInMemoryCache(t)

	// unlike the python cataloger we intentionally do not cache failed lookups: a transient
	// registry failure must not be able to blank out licenses for the lifetime of the cache entry
	stub := newNpmRegistryStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprintf(w, `too many requests`) // not valid JSON
	})

	lr := newJavascriptLicenseResolver(stub.config())

	for i := 0; i < 3; i++ {
		_, err := lr.getLicensesFromRemote("@babel/code-frame", "7.10.4")
		require.Error(t, err)
	}

	assert.Equal(t, int64(3), stub.requests.Load(), "expected every lookup to be retried against the registry")
}

func TestJavascriptLicenseResolver_keyIncludesNameAndVersion(t *testing.T) {
	useInMemoryCache(t)

	stub := newNpmRegistryStub(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"license": %q}`, r.URL.Path)
	})

	lr := newJavascriptLicenseResolver(stub.config())

	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{name: "lodash", version: "4.17.21", expected: "/lodash/4.17.21"},
		{name: "lodash", version: "4.17.20", expected: "/lodash/4.17.20"},
		{name: "@babel/code-frame", version: "7.10.4", expected: "/@babel/code-frame/7.10.4"},
	}

	for _, tt := range tests {
		license, err := lr.getLicensesFromRemote(tt.name, tt.version)
		require.NoError(t, err)
		assert.Equal(t, tt.expected, license)
	}

	assert.Equal(t, int64(len(tests)), stub.requests.Load())
}

func TestJavascriptLicenseResolver_getLicenses(t *testing.T) {
	ctx := context.TODO()

	tests := []struct {
		name             string
		searchRemote     bool
		response         string
		expected         pkg.LicenseSet
		expectedRequests int64
	}{
		{
			name:             "remote search disabled makes no request",
			searchRemote:     false,
			response:         `{"license": "MIT"}`,
			expected:         pkg.LicenseSet{},
			expectedRequests: 0,
		},
		{
			name:             "remote search returns the license from the registry",
			searchRemote:     true,
			response:         `{"license": "MIT"}`,
			expected:         pkg.NewLicenseSet(pkg.NewLicenseWithContext(ctx, "MIT")),
			expectedRequests: 1,
		},
		{
			name:             "an empty license yields an empty license set",
			searchRemote:     true,
			response:         `{"name": "no-license-pkg"}`,
			expected:         pkg.LicenseSet{},
			expectedRequests: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useInMemoryCache(t)

			stub := newNpmRegistryStub(t, func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, tt.response)
			})

			cfg := stub.config()
			cfg.SearchRemoteLicenses = tt.searchRemote
			lr := newJavascriptLicenseResolver(cfg)

			assert.Equal(t, tt.expected, lr.getLicenses(ctx, "some-pkg", "1.0.0"))
			assert.Equal(t, tt.expectedRequests, stub.requests.Load())
		})
	}
}
