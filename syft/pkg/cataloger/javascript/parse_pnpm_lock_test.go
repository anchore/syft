package javascript

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParsePnpmLock(t *testing.T) {
	var expectedRelationships []artifact.Relationship
	fixture := "test-fixtures/pnpm/pnpm-lock.yaml"

	locationSet := file.NewLocationSet(file.NewLocation(fixture))

	expectedPkgs := []pkg.Package{
		{
			Name:      "nanoid",
			Version:   "3.3.4",
			PURL:      "pkg:npm/nanoid@3.3.4",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "picocolors",
			Version:   "1.0.0",
			PURL:      "pkg:npm/picocolors@1.0.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "source-map-js",
			Version:   "1.0.2",
			PURL:      "pkg:npm/source-map-js@1.0.2",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "@bcoe/v8-coverage",
			Version:   "0.2.3",
			PURL:      "pkg:npm/%40bcoe/v8-coverage@0.2.3",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
	}

	adapter := newGenericPnpmLockAdapter(CatalogerConfig{})
	pkgtest.TestFileParser(t, fixture, adapter.parsePnpmLock, expectedPkgs, expectedRelationships)
}

func TestParsePnpmV6Lock(t *testing.T) {
	var expectedRelationships []artifact.Relationship
	fixture := "test-fixtures/pnpm-v6/pnpm-lock.yaml"

	locationSet := file.NewLocationSet(file.NewLocation(fixture))

	expectedPkgs := []pkg.Package{
		{
			Name:      "@testing-library/jest-dom",
			Version:   "5.16.5",
			PURL:      "pkg:npm/%40testing-library/jest-dom@5.16.5",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "@testing-library/react",
			Version:   "13.4.0",
			PURL:      "pkg:npm/%40testing-library/react@13.4.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "@testing-library/user-event",
			Version:   "13.5.0",
			PURL:      "pkg:npm/%40testing-library/user-event@13.5.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "react",
			Version:   "18.2.0",
			PURL:      "pkg:npm/react@18.2.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "react-dom",
			Version:   "18.2.0",
			PURL:      "pkg:npm/react-dom@18.2.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "web-vitals",
			Version:   "2.1.4",
			PURL:      "pkg:npm/web-vitals@2.1.4",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "@babel/core",
			Version:   "7.21.4",
			PURL:      "pkg:npm/%40babel/core@7.21.4",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "@types/eslint",
			Version:   "8.37.0",
			PURL:      "pkg:npm/%40types/eslint@8.37.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "read-cache",
			Version:   "1.0.0",
			PURL:      "pkg:npm/read-cache@1.0.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "schema-utils",
			Version:   "3.1.2",
			PURL:      "pkg:npm/schema-utils@3.1.2",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
	}

	adapter := newGenericPnpmLockAdapter(CatalogerConfig{})
	pkgtest.TestFileParser(t, fixture, adapter.parsePnpmLock, expectedPkgs, expectedRelationships)
}

func TestParsePnpmLockV9(t *testing.T) {
	var expectedRelationships []artifact.Relationship
	fixture := "test-fixtures/pnpm-v9/pnpm-lock.yaml"
	locationSet := file.NewLocationSet(file.NewLocation(fixture))

	expected := []pkg.Package{
		{
			Name:      "@babel/core",
			Version:   "7.24.7",
			PURL:      "pkg:npm/%40babel/core@7.24.7",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "@babel/helper-plugin-utils",
			Version:   "7.24.7",
			PURL:      "pkg:npm/%40babel/helper-plugin-utils@7.24.7",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "is-positive",
			Version:   "3.1.0",
			PURL:      "pkg:npm/is-positive@3.1.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "rollup",
			Version:   "4.18.0",
			PURL:      "pkg:npm/rollup@4.18.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
	}
	adapter := newGenericPnpmLockAdapter(CatalogerConfig{})
	// TODO: no relationships are under test
	pkgtest.TestFileParser(t, fixture, adapter.parsePnpmLock, expected, expectedRelationships)
}

func TestSearchPnpmForLicenses(t *testing.T) {
	ctx := context.TODO()
	fixture := "test-fixtures/pnpm-remote/pnpm-lock.yaml"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	mux, url, teardown := setupNpmRegistry()
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
					// https://registry.npmjs.org/nanoid/3.3.4
					path:    "/nanoid/3.3.4",
					handler: generateMockNpmRegistryHandler("test-fixtures/pnpm-remote/registry_response.json"),
				},
			},
			expectedPackages: []pkg.Package{
				{
					Name:      "nanoid",
					Version:   "3.3.4",
					Locations: locations,
					PURL:      "pkg:npm/nanoid@3.3.4",
					Licenses:  pkg.NewLicenseSet(pkg.NewLicenseWithContext(ctx, "MIT")),
					Language:  pkg.JavaScript,
					Type:      pkg.NpmPkg,
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
			adapter := newGenericPnpmLockAdapter(tc.config)
			pkgtest.TestFileParser(t, fixture, adapter.parsePnpmLock, tc.expectedPackages, nil)
		})
	}
}
func Test_corruptPnpmLock(t *testing.T) {
	adapter := newGenericPnpmLockAdapter(CatalogerConfig{})
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/corrupt/pnpm-lock.yaml").
		WithError().
		TestParser(t, adapter.parsePnpmLock)
}

func generateMockNpmRegistryHandler(responseFixture string) func(w http.ResponseWriter, r *http.Request) {
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

// setup sets up a test HTTP server for mocking requests to a particular registry.
// The returned url is injected into the Config so the client uses the test server.
// Tests should register handlers on mux to simulate the expected request/response structure
func setupNpmRegistry() (mux *http.ServeMux, serverURL string, teardown func()) {
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
