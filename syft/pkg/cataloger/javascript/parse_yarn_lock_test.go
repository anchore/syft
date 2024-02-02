package javascript

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseYarnBerry(t *testing.T) {
	var expectedRelationships []artifact.Relationship
	fixture := "test-fixtures/yarn-berry/yarn.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))

	expectedPkgs := []pkg.Package{
		{
			Name:      "@babel/code-frame",
			Version:   "7.10.4",
			Locations: locations,
			PURL:      "pkg:npm/%40babel/code-frame@7.10.4",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.YarnLockEntry{},
		},
		{
			Name:      "@types/minimatch",
			Version:   "3.0.3",
			Locations: locations,
			PURL:      "pkg:npm/%40types/minimatch@3.0.3",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.YarnLockEntry{},
		},
		{
			Name:      "@types/qs",
			Version:   "6.9.4",
			Locations: locations,
			PURL:      "pkg:npm/%40types/qs@6.9.4",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.YarnLockEntry{},
		},
		{
			Name:      "ajv",
			Version:   "6.12.3",
			Locations: locations,
			PURL:      "pkg:npm/ajv@6.12.3",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.YarnLockEntry{},
		},
		{
			Name:      "asn1.js",
			Version:   "4.10.1",
			Locations: locations,
			PURL:      "pkg:npm/asn1.js@4.10.1",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.YarnLockEntry{},
		},
		{
			Name:      "atob",
			Version:   "2.1.2",
			Locations: locations,
			PURL:      "pkg:npm/atob@2.1.2",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.YarnLockEntry{},
		},
		{
			Name:      "aws-sdk",
			Version:   "2.706.0",
			PURL:      "pkg:npm/aws-sdk@2.706.0",
			Locations: locations,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.YarnLockEntry{},
		},
		{
			Name:      "c0n-fab_u.laTION",
			Version:   "7.7.7",
			Locations: locations,
			PURL:      "pkg:npm/c0n-fab_u.laTION@7.7.7",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.YarnLockEntry{},
		},
		{
			Name:      "jhipster-core",
			Version:   "7.3.4",
			Locations: locations,
			PURL:      "pkg:npm/jhipster-core@7.3.4",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.YarnLockEntry{},
		},
	}

	adapter := newGenericYarnLockAdapter(CatalogerConfig{})
	pkgtest.TestFileParser(t, fixture, adapter.parseYarnLock, expectedPkgs, expectedRelationships)
}

func TestParseYarnLock(t *testing.T) {
	var expectedRelationships []artifact.Relationship
	fixture := "test-fixtures/yarn/yarn.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))

	expectedPkgs := []pkg.Package{
		{
			Name:      "@babel/code-frame",
			Version:   "7.10.4",
			Locations: locations,
			PURL:      "pkg:npm/%40babel/code-frame@7.10.4",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.10.4.tgz#168da1a36e90da68ae8d49c0f1b48c7c6249213a",
				Integrity: "sha512-vG6SvB6oYEhvgisZNFRmRCUkLz11c7rp+tbNTynGqc6mS1d5ATd/sGyV6W0KZZnXRKMTzZDRgQT3Ou9jhpAfUg==",
			},
		},
		{
			Name:      "@types/minimatch",
			Version:   "3.0.3",
			Locations: locations,
			PURL:      "pkg:npm/%40types/minimatch@3.0.3",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "https://registry.yarnpkg.com/@types/minimatch/-/minimatch-3.0.3.tgz#3dca0e3f33b200fc7d1139c0cd96c1268cadfd9d",
				Integrity: "sha512-tHq6qdbT9U1IRSGf14CL0pUlULksvY9OZ+5eEgl1N7t+OA3tGvNpxJCzuKQlsNgCVwbAs670L1vcVQi8j9HjnA==",
			},
		},
		{
			Name:      "@types/qs",
			Version:   "6.9.4",
			Locations: locations,
			PURL:      "pkg:npm/%40types/qs@6.9.4",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "https://registry.yarnpkg.com/@types/qs/-/qs-6.9.4.tgz#a59e851c1ba16c0513ea123830dd639a0a15cb6a",
				Integrity: "sha512-+wYo+L6ZF6BMoEjtf8zB2esQsqdV6WsjRK/GP9WOgLPrq87PbNWgIxS76dS5uvl/QXtHGakZmwTznIfcPXcKlQ==",
			},
		},
		{
			Name:      "ajv",
			Version:   "6.12.3",
			Locations: locations,
			PURL:      "pkg:npm/ajv@6.12.3",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "https://registry.yarnpkg.com/ajv/-/ajv-6.12.3.tgz#18c5af38a111ddeb4f2697bd78d68abc1cabd706",
				Integrity: "sha512-4K0cK3L1hsqk9xIb2z9vs/XU+PGJZ9PNpJRDS9YLzmNdX6jmVPfamLvTJr0aDAusnHyCHO6MjzlkAsgtqp9teA==",
			},
		},
		{
			Name:      "asn1.js",
			Version:   "4.10.1",
			Locations: locations,
			PURL:      "pkg:npm/asn1.js@4.10.1",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "https://registry.yarnpkg.com/asn1.js/-/asn1.js-4.10.1.tgz#b9c2bf5805f1e64aadeed6df3a2bfafb5a73f5a0",
				Integrity: "sha512-p32cOF5q0Zqs9uBiONKYLm6BClCoBCM5O9JfeUSlnQLBTxYdTK+pW+nXflm8UkKd2UYlEbYz5qEi0JuZR9ckSw==",
			},
		},
		{
			Name:      "atob",
			Version:   "2.1.2",
			Locations: locations,

			PURL:     "pkg:npm/atob@2.1.2",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "https://registry.yarnpkg.com/atob/-/atob-2.1.2.tgz#6d9517eb9e030d2436666651e86bd9f6f13533c9",
				Integrity: "sha512-Wm6ukoaOGJi/73p/cl2GvLjTI5JM1k/O14isD73YML8StrH/7/lRFgmg8nICZgD3bZZvjwCGxtMOD3wWNAu8cg==",
			},
		},
		{
			Name:      "aws-sdk",
			Version:   "2.706.0",
			Locations: locations,
			PURL:      "pkg:npm/aws-sdk@2.706.0",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "https://registry.yarnpkg.com/aws-sdk/-/aws-sdk-2.706.0.tgz#09f65e9a91ecac5a635daf934082abae30eca953",
				Integrity: "sha512-7GT+yrB5Wb/zOReRdv/Pzkb2Qt+hz6B/8FGMVaoysX3NryHvQUdz7EQWi5yhg9CxOjKxdw5lFwYSs69YlSp1KA==",
			},
		},
		{
			Name:      "jhipster-core",
			Version:   "7.3.4",
			Locations: locations,
			PURL:      "pkg:npm/jhipster-core@7.3.4",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "https://registry.yarnpkg.com/jhipster-core/-/jhipster-core-7.3.4.tgz#c34b8c97c7f4e8b7518dae015517e2112c73cc80",
				Integrity: "sha512-AUhT69kNkqppaJZVfan/xnKG4Gs9Ggj7YLtTZFVe+xg+THrbMb5Ng7PL07PDlDw4KAEA33GMCwuAf65E8EpC4g==",
			},
		},
		{
			Name:      "something-i-made-up",
			Version:   "7.7.7",
			Locations: locations,
			PURL:      "pkg:npm/something-i-made-up@7.7.7",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "https://registry.yarnpkg.com/something-i-made-up/-/c0n-fab_u.laTION-7.7.7.tgz#b9c2bf5805f1e64aadeed6df3a2bfafb5a73f5a0",
				Integrity: "sha512-p32cOF5q0Zqs9uBiONKYLm6BClCoBCM5O9JfeUSlnQLBTxYdTK+pW+nXflm8UkKd2UYlEbYz5qEi0JuZR9ckSw==",
			},
		},
	}

	adapter := newGenericYarnLockAdapter(CatalogerConfig{})
	pkgtest.TestFileParser(t, fixture, adapter.parseYarnLock, expectedPkgs, expectedRelationships)
}

type handlerPath struct {
	path    string
	handler func(w http.ResponseWriter, r *http.Request)
}

func TestSearchYarnForLicenses(t *testing.T) {
	fixture := "test-fixtures/yarn-remote/yarn.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	mux, url, teardown := setup()
	defer teardown()
	tests := []struct {
		name             string
		fixture          string
		config           CatalogerConfig
		requestHandlers  []handlerPath
		expectedPackages []pkg.Package
	}{
		{
			name:   "search remote licenses returns the expected licenses when search is set to true",
			config: CatalogerConfig{SearchRemoteLicenses: true},
			requestHandlers: []handlerPath{
				{
					// https://registry.yarnpkg.com/@babel/code-frame/7.10.4
					path:    "/@babel/code-frame/7.10.4",
					handler: generateMockNPMHandler("test-fixtures/yarn-remote/registry_response.json"),
				},
			},
			expectedPackages: []pkg.Package{
				{
					Name:      "@babel/code-frame",
					Version:   "7.10.4",
					Locations: locations,
					PURL:      "pkg:npm/%40babel/code-frame@7.10.4",
					Licenses:  pkg.NewLicenseSet(pkg.NewLicense("MIT")),
					Language:  pkg.JavaScript,
					Type:      pkg.NpmPkg,
					Metadata: pkg.YarnLockEntry{
						Resolved:  "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.10.4.tgz#168da1a36e90da68ae8d49c0f1b48c7c6249213a",
						Integrity: "sha512-vG6SvB6oYEhvgisZNFRmRCUkLz11c7rp+tbNTynGqc6mS1d5ATd/sGyV6W0KZZnXRKMTzZDRgQT3Ou9jhpAfUg==",
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// set up the mock server
			for _, handler := range tc.requestHandlers {
				mux.HandleFunc(handler.path, handler.handler)
			}
			tc.config.NPMBaseURL = url
			adapter := newGenericYarnLockAdapter(tc.config)
			pkgtest.TestFileParser(t, fixture, adapter.parseYarnLock, tc.expectedPackages, nil)
		})
	}
}

func TestParseYarnFindPackageNames(t *testing.T) {
	tests := []struct {
		line     string
		expected string
	}{
		{
			line:     `"@babel/code-frame@npm:7.10.4":`,
			expected: "@babel/code-frame",
		},
		{
			line:     `"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":`,
			expected: "@babel/code-frame",
		},
		{
			line:     "ajv@^6.10.2, ajv@^6.5.5:",
			expected: "ajv",
		},
		{
			line:     "aws-sdk@2.706.0:",
			expected: "aws-sdk",
		},
		{
			line:     "asn1.js@^4.0.0:",
			expected: "asn1.js",
		},
		{
			line:     "c0n-fab_u.laTION@^7.0.0",
			expected: "c0n-fab_u.laTION",
		},
		{
			line:     `"newtest@workspace:.":`,
			expected: "newtest",
		},
		{
			line:     `"color-convert@npm:^1.9.0":`,
			expected: "color-convert",
		},
		{
			line:     `"@npmcorp/code-frame@^7.1.0", "@npmcorp/code-frame@^7.10.4":`,
			expected: "@npmcorp/code-frame",
		},
		{
			line:     `"@npmcorp/code-frame@^7.2.3":`,
			expected: "@npmcorp/code-frame",
		},
		{
			line:     `"@s/odd-name@^7.1.2":`,
			expected: "@s/odd-name",
		},
		{
			line:     `"@/code-frame@^7.3.4":`,
			expected: "",
		},
		{
			line:     `"code-frame":`,
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			t.Parallel()
			actual := findPackageName(test.line)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestParseYarnFindPackageVersions(t *testing.T) {
	tests := []struct {
		line     string
		expected string
	}{
		{
			line:     `  version "7.10.4"`,
			expected: "7.10.4",
		},
		{
			line:     ` version "7.11.5"`,
			expected: "7.11.5",
		},
		{
			line:     `version "7.12.6"`,
			expected: "",
		},
		{
			line:     `  version "0.0.0"`,
			expected: "0.0.0",
		},
		{
			line:     `  version "2" `,
			expected: "2",
		},
		{
			line:     `  version "9.3"`,
			expected: "9.3",
		},
		{
			line:     "ajv@^6.10.2, ajv@^6.5.5",
			expected: "",
		},
		{
			line:     "atob@^2.1.2:",
			expected: "",
		},
		{
			line:     `"color-convert@npm:^1.9.0":`,
			expected: "",
		},
		{
			line:     "  version: 1.9.3",
			expected: "1.9.3",
		},
		{
			line:     "  version: 2",
			expected: "2",
		},
		{
			line:     "  version: 9.3",
			expected: "9.3",
		},
		{
			line:     "ajv@^6.10.2, ajv@^6.5.5",
			expected: "",
		},
		{
			line:     "atob@^2.1.2:",
			expected: "",
		},
		{
			line:     "  version: 1.0.0-alpha+001",
			expected: "1.0.0-alpha",
		},
		{
			line:     "  version: 1.0.0-beta_test+exp.sha.5114f85",
			expected: "1.0.0-beta_test",
		},
		{
			line:     "  version: 1.0.0+21AF26D3-117B344092BD",
			expected: "1.0.0",
		},
		{
			line:     "  version: 0.0.0-use.local",
			expected: "0.0.0-use.local",
		},
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			t.Parallel()
			actual := findPackageVersion(test.line)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func generateMockNPMHandler(responseFixture string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Copy the file's content to the response writer
		file, err := os.Open(responseFixture)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = io.Copy(w, file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

// setup sets up a test HTTP server for mocking requests to maven central.
// The returned url is injected into the Config so the client uses the test server.
// Tests should register handlers on mux to simulate the expected request/response structure
func setup() (mux *http.ServeMux, serverURL string, teardown func()) {
	// mux is the HTTP request multiplexer used with the test server.
	mux = http.NewServeMux()

	// We want to ensure that tests catch mistakes where the endpoint URL is
	// specified as absolute rather than relative. It only makes a difference
	// when there's a non-empty base URL path. So, use that. See issue #752.
	apiHandler := http.NewServeMux()
	apiHandler.Handle("/", mux)
	// server is a test HTTP server used to provide mock API responses.
	server := httptest.NewServer(apiHandler)

	return mux, server.URL, server.Close
}
