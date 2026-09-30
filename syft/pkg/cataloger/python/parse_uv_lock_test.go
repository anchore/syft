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
	fixture := "testdata/uv/simple-deps/uv.lock"

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

func TestParseUvLockForkedVersions(t *testing.T) {
	fixture := "testdata/uv/forked-versions/uv.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	index := "https://pypi.org/simple"

	newPkg := func(name, version string, meta pkg.PythonUvLockEntry) pkg.Package {
		return pkg.Package{
			Name:      name,
			Version:   version,
			Locations: locations,
			PURL:      "pkg:pypi/" + name + "@" + version,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata:  meta,
		}
	}

	forkdemo := newPkg("forkdemo", "0.1.0", pkg.PythonUvLockEntry{
		Index: ".",
		Dependencies: []pkg.PythonUvLockDependencyEntry{
			{Name: "pandas", Markers: "python_full_version < '3.11'"},
			{Name: "pandas", Markers: "python_full_version >= '3.11'"},
		},
		Extras: []pkg.PythonUvLockExtraEntry{
			{Name: "legacy", Dependencies: []string{"numpy"}},
		},
	})
	numpy1264 := newPkg("numpy", "1.26.4", pkg.PythonUvLockEntry{Index: index})
	numpy226 := newPkg("numpy", "2.2.6", pkg.PythonUvLockEntry{Index: index})
	numpy246 := newPkg("numpy", "2.4.6", pkg.PythonUvLockEntry{Index: index})
	numpy253 := newPkg("numpy", "2.5.3", pkg.PythonUvLockEntry{Index: index})
	pandas233 := newPkg("pandas", "2.3.3", pkg.PythonUvLockEntry{
		Index: index,
		Dependencies: []pkg.PythonUvLockDependencyEntry{
			{Name: "numpy", Markers: "python_full_version < '3.10'"},
			{Name: "numpy", Markers: "python_full_version == '3.10.*'"},
		},
	})
	pandas306 := newPkg("pandas", "3.0.6", pkg.PythonUvLockEntry{
		Index: index,
		Dependencies: []pkg.PythonUvLockDependencyEntry{
			{Name: "numpy", Markers: "python_full_version == '3.11.*'"},
			{Name: "numpy", Markers: "python_full_version >= '3.12'"},
		},
	})

	dependencyOf := func(from, to pkg.Package) artifact.Relationship {
		return artifact.Relationship{From: from, To: to, Type: artifact.DependencyOfRelationship}
	}

	// each dependent links only to the versions its entries name, including through an optional dependency
	expectedRelationships := []artifact.Relationship{
		dependencyOf(pandas233, forkdemo),
		dependencyOf(pandas306, forkdemo),
		dependencyOf(numpy1264, forkdemo),
		dependencyOf(numpy1264, pandas233),
		dependencyOf(numpy226, pandas233),
		dependencyOf(numpy246, pandas306),
		dependencyOf(numpy253, pandas306),
	}

	uvLockParser := newUvLockParser(DefaultCatalogerConfig())
	pkgtest.TestFileParser(t, fixture, uvLockParser.parseUvLock, []pkg.Package{
		forkdemo,
		numpy1264,
		numpy226,
		numpy246,
		numpy253,
		pandas233,
		pandas306,
	}, expectedRelationships)
}

func TestParseUvLockWithLicenseEnrichment(t *testing.T) {
	ctx := context.TODO()
	fixture := "testdata/pypi-remote/uv.lock"
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
					handler: generateMockPypiRegistryHandler("testdata/pypi-remote/registry_response.json"),
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
