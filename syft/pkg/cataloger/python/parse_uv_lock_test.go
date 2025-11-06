package python

import (
	"context"
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseUvLock(t *testing.T) {
	fixture := "test-fixtures/uv/simple-deps/uv.lock"

	locations := file.NewLocationSet(file.NewLocation(fixture))

	certifi := pkg.Package{
		Name:      "certifi",
		Version:   "2025.1.31",
		Locations: locations,
		PURL:      "pkg:pypi/certifi@2025.1.31",
		Language:  pkg.Python,
		Type:      pkg.PythonPkg,
		Metadata:  pkg.PythonUvLockEntry{Index: "https://pypi.org/simple"},
	}

	charsetNormalizer := pkg.Package{
		Name:      "charset-normalizer",
		Version:   "3.4.1",
		Locations: locations,
		PURL:      "pkg:pypi/charset-normalizer@3.4.1",
		Language:  pkg.Python,
		Type:      pkg.PythonPkg,
		Metadata:  pkg.PythonUvLockEntry{Index: "https://pypi.org/simple"},
	}

	idna := pkg.Package{
		Name:      "idna",
		Version:   "3.10",
		Locations: locations,
		PURL:      "pkg:pypi/idna@3.10",
		Language:  pkg.Python,
		Type:      pkg.PythonPkg,
		Metadata:  pkg.PythonUvLockEntry{Index: "https://pypi.org/simple"},
	}

	requests := pkg.Package{
		Name:      "requests",
		Version:   "2.32.3",
		Locations: locations,
		PURL:      "pkg:pypi/requests@2.32.3",
		Language:  pkg.Python,
		Type:      pkg.PythonPkg,
		Metadata: pkg.PythonUvLockEntry{
			Index: "https://pypi.org/simple",
			Dependencies: []pkg.PythonUvLockDependencyEntry{
				{Name: "certifi"},
				{Name: "charset-normalizer"},
				{Name: "idna"},
				{Name: "urllib3"},
			},
		},
	}

	testpkg := pkg.Package{
		Name:      "testpkg",
		Version:   "0.1.0",
		Locations: locations,
		PURL:      "pkg:pypi/testpkg@0.1.0",
		Language:  pkg.Python,
		Type:      pkg.PythonPkg,
		Metadata: pkg.PythonUvLockEntry{
			Index: ".", // virtual
			Dependencies: []pkg.PythonUvLockDependencyEntry{
				{Name: "requests"},
			},
		},
	}

	urllib3 := pkg.Package{
		Name:      "urllib3",
		Version:   "2.3.0",
		Locations: locations,
		PURL:      "pkg:pypi/urllib3@2.3.0",
		Language:  pkg.Python,
		Type:      pkg.PythonPkg,
		Metadata:  pkg.PythonUvLockEntry{Index: "https://pypi.org/simple"},
	}

	expectedPkgs := []pkg.Package{
		certifi,
		charsetNormalizer,
		idna,
		requests,
		testpkg,
		urllib3,
	}

	expectedRelationships := []artifact.Relationship{
		{
			From: certifi,
			To:   requests,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: charsetNormalizer,
			To:   requests,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: idna,
			To:   requests,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: requests,
			To:   testpkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: urllib3,
			To:   requests,
			Type: artifact.DependencyOfRelationship,
		},
	}

	uvLockParser := newUvLockParser(DefaultCatalogerConfig())
	pkgtest.TestFileParser(t, fixture, uvLockParser.parseUvLock, expectedPkgs, expectedRelationships)
}

func TestParseUvLockWithLicenseEnrichment(t *testing.T) {
	ctx := context.TODO()
	fixture := "test-fixtures/pypi-remote/uv.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	mux, url, teardown := setupPypiRegistry()
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
					path:    "/certifi/2025.10.5/json",
					handler: generateMockPypiRegistryHandler("test-fixtures/pypi-remote/registry_response.json"),
				},
			},
			expectedPackages: []pkg.Package{
				{
					Name:      "certifi",
					Version:   "2025.10.5",
					Locations: locations,
					PURL:      "pkg:pypi/certifi@2025.10.5",
					Licenses:  pkg.NewLicenseSet(pkg.NewLicenseWithContext(ctx, "MPL-2.0")),
					Language:  pkg.Python,
					Type:      pkg.PythonPkg,
					Metadata: pkg.PythonUvLockEntry{
						Index:        "https://pypi.org/simple",
						Dependencies: nil,
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
			tc.config.PypiBaseURL = url
			uvLockParser := newUvLockParser(tc.config)
			pkgtest.TestFileParser(t, fixture, uvLockParser.parseUvLock, tc.expectedPackages, nil)
		})
	}
}
