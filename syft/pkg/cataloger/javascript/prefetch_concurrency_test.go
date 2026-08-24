package javascript

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	gosync "github.com/anchore/go-sync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cataloging"
)

func networkContext(maxConcurrency int) context.Context {
	return gosync.SetContextExecutor(context.Background(), cataloging.ExecutorNetwork, gosync.NewExecutor(maxConcurrency))
}

func TestNpmLicensePrefetchWarmsResolver(t *testing.T) {
	mux, url, teardown := setupNpmRegistry()
	defer teardown()

	var requests atomic.Int64
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, `{"license":"MIT"}`)
	})

	resolver := newJavascriptLicenseResolver(CatalogerConfig{SearchRemoteLicenses: true, NPMBaseURL: url})
	pairs := [][2]string{{"pkg-a", "1.0.0"}, {"pkg-b", "2.0.0"}}
	prefetchNpmLicenses(networkContext(2), resolver, pairs)

	for _, pair := range pairs {
		license, err := resolver.getLicensesFromRemote(pair[0], pair[1])
		require.NoError(t, err)
		assert.Equal(t, "MIT", license)
	}
	assert.Equal(t, int64(2), requests.Load(), "package construction should reuse prefetched values")
}

func TestNpmLicensePrefetchDeduplicatesPairs(t *testing.T) {
	mux, url, teardown := setupNpmRegistry()
	defer teardown()

	var requests atomic.Int64
	mux.HandleFunc("/pkg-a/1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, `{"license":"MIT"}`)
	})

	resolver := newJavascriptLicenseResolver(CatalogerConfig{SearchRemoteLicenses: true, NPMBaseURL: url})
	prefetchNpmLicenses(networkContext(2), resolver, [][2]string{
		{"pkg-a", "1.0.0"},
		{"pkg-a", "1.0.0"},
	})

	assert.Equal(t, int64(1), requests.Load())
}

func TestNpmLicensePrefetchSkipsWhenDisabled(t *testing.T) {
	mux, url, teardown := setupNpmRegistry()
	defer teardown()

	var requests atomic.Int64
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, `{"license":"MIT"}`)
	})

	resolver := newJavascriptLicenseResolver(CatalogerConfig{NPMBaseURL: url})
	prefetchNpmLicenses(networkContext(2), resolver, [][2]string{{"pkg-a", "1.0.0"}})

	assert.Zero(t, requests.Load())
}

func TestNpmLicensePrefetchUsesNetworkExecutorBound(t *testing.T) {
	mux, url, teardown := setupNpmRegistry()
	defer teardown()

	var active atomic.Int64
	var highWater atomic.Int64
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			observed := highWater.Load()
			if current <= observed || highWater.CompareAndSwap(observed, current) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		fmt.Fprint(w, `{"license":"MIT"}`)
	})

	resolver := newJavascriptLicenseResolver(CatalogerConfig{SearchRemoteLicenses: true, NPMBaseURL: url})
	pairs := make([][2]string, 0, 6)
	for i := 0; i < 6; i++ {
		pairs = append(pairs, [2]string{fmt.Sprintf("pkg-%d", i), "1.0.0"})
	}
	prefetchNpmLicenses(networkContext(2), resolver, pairs)

	assert.Equal(t, int64(2), highWater.Load(), "network requests should use the configured executor bound")
}

func TestNpmLicensePrefetchContinuesAfterError(t *testing.T) {
	mux, url, teardown := setupNpmRegistry()
	defer teardown()

	var goodRequests atomic.Int64
	mux.HandleFunc("/bad-pkg/1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	mux.HandleFunc("/good-pkg/1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		goodRequests.Add(1)
		fmt.Fprint(w, `{"license":"MIT"}`)
	})

	resolver := newJavascriptLicenseResolver(CatalogerConfig{SearchRemoteLicenses: true, NPMBaseURL: url})
	prefetchNpmLicenses(networkContext(2), resolver, [][2]string{
		{"bad-pkg", "1.0.0"},
		{"good-pkg", "1.0.0"},
	})

	assert.Equal(t, int64(1), goodRequests.Load())
}
