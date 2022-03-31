package python

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/go-test/deep"
)

func TestPythonPackageWheelCataloger(t *testing.T) {
	tests := []struct {
		name            string
		fixtures        []string
		expectedPackage pkg.Package
	}{
		{
			name: "egg-info directory",
			fixtures: []string{
				"test-fixtures/egg-info/PKG-INFO",
				"test-fixtures/egg-info/RECORD",
				"test-fixtures/egg-info/top_level.txt",
			},
			expectedPackage: pkg.Package{
				Name:         "requests",
				Version:      "2.22.0",
				Type:         pkg.PythonPkg,
				Language:     pkg.Python,
				Licenses:     []string{"Apache 2.0"},
				FoundBy:      "python-package-cataloger",
				MetadataType: pkg.PythonPackageMetadataType,
				Metadata: pkg.PythonPackageMetadata{
					Name:                 "requests",
					Version:              "2.22.0",
					License:              "Apache 2.0",
					Platform:             "UNKNOWN",
					Author:               "Kenneth Reitz",
					AuthorEmail:          "me@kennethreitz.org",
					SitePackagesRootPath: "test-fixtures",
					Files: []pkg.PythonFileRecord{
						{Path: "requests-2.22.0.dist-info/INSTALLER", Digest: &pkg.PythonFileDigest{"sha256", "zuuue4knoyJ-UwPPXg8fezS7VCrXJQrAP7zeNuwvFQg"}, Size: "4"},
						{Path: "requests/__init__.py", Digest: &pkg.PythonFileDigest{"sha256", "PnKCgjcTq44LaAMzB-7--B2FdewRrE8F_vjZeaG9NhA"}, Size: "3921"},
						{Path: "requests/__pycache__/__version__.cpython-38.pyc"},
						{Path: "requests/__pycache__/utils.cpython-38.pyc"},
						{Path: "requests/__version__.py", Digest: &pkg.PythonFileDigest{"sha256", "Bm-GFstQaFezsFlnmEMrJDe8JNROz9n2XXYtODdvjjc"}, Size: "436"},
						{Path: "requests/utils.py", Digest: &pkg.PythonFileDigest{"sha256", "LtPJ1db6mJff2TJSJWKi7rBpzjPS3mSOrjC9zRhoD3A"}, Size: "30049"},
					},
					TopLevelPackages: []string{"requests"},
				},
			},
		},
		{
			name: "dist-info directory",
			fixtures: []string{
				"test-fixtures/dist-info/METADATA",
				"test-fixtures/dist-info/RECORD",
				"test-fixtures/dist-info/top_level.txt",
				"test-fixtures/dist-info/direct_url.json",
			},
			expectedPackage: pkg.Package{
				Name:         "Pygments",
				Version:      "2.6.1",
				Type:         pkg.PythonPkg,
				Language:     pkg.Python,
				Licenses:     []string{"BSD License"},
				FoundBy:      "python-package-cataloger",
				MetadataType: pkg.PythonPackageMetadataType,
				Metadata: pkg.PythonPackageMetadata{
					Name:                 "Pygments",
					Version:              "2.6.1",
					License:              "BSD License",
					Platform:             "any",
					Author:               "Georg Brandl",
					AuthorEmail:          "georg@python.org",
					SitePackagesRootPath: "test-fixtures",
					Files: []pkg.PythonFileRecord{
						{Path: "../../../bin/pygmentize", Digest: &pkg.PythonFileDigest{"sha256", "dDhv_U2jiCpmFQwIRHpFRLAHUO4R1jIJPEvT_QYTFp8"}, Size: "220"},
						{Path: "Pygments-2.6.1.dist-info/AUTHORS", Digest: &pkg.PythonFileDigest{"sha256", "PVpa2_Oku6BGuiUvutvuPnWGpzxqFy2I8-NIrqCvqUY"}, Size: "8449"},
						{Path: "Pygments-2.6.1.dist-info/RECORD"},
						{Path: "pygments/__pycache__/__init__.cpython-38.pyc"},
						{Path: "pygments/util.py", Digest: &pkg.PythonFileDigest{"sha256", "586xXHiJGGZxqk5PMBu3vBhE68DLuAe5MBARWrSPGxA"}, Size: "10778"},

						{Path: "pygments/x_util.py", Digest: &pkg.PythonFileDigest{"sha256", "qpzzsOW31KT955agi-7NS--90I0iNiJCyLJQnRCHgKI="}, Size: "10778"},
					},
					TopLevelPackages: []string{"pygments", "something_else"},
					DirectURLOrigin:  &pkg.PythonDirectURLOriginInfo{URL: "https://github.com/python-test/test.git", VCS: "git", CommitID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
				},
			},
		},
		{
			// in cases where the metadata file is available and the record is not we should still record there is a package
			// additionally empty top_level.txt files should not result in an error
			name:     "partial dist-info directory",
			fixtures: []string{"test-fixtures/partial.dist-info/METADATA"},
			expectedPackage: pkg.Package{
				Name:         "Pygments",
				Version:      "2.6.1",
				Type:         pkg.PythonPkg,
				Language:     pkg.Python,
				Licenses:     []string{"BSD License"},
				FoundBy:      "python-package-cataloger",
				MetadataType: pkg.PythonPackageMetadataType,
				Metadata: pkg.PythonPackageMetadata{
					Name:                 "Pygments",
					Version:              "2.6.1",
					License:              "BSD License",
					Platform:             "any",
					Author:               "Georg Brandl",
					AuthorEmail:          "georg@python.org",
					SitePackagesRootPath: "test-fixtures",
				},
			},
		},
		{
			name:     "egg-info regular file",
			fixtures: []string{"test-fixtures/test.egg-info"},
			expectedPackage: pkg.Package{
				Name:         "requests",
				Version:      "2.22.0",
				Type:         pkg.PythonPkg,
				Language:     pkg.Python,
				Licenses:     []string{"Apache 2.0"},
				FoundBy:      "python-package-cataloger",
				MetadataType: pkg.PythonPackageMetadataType,
				Metadata: pkg.PythonPackageMetadata{
					Name:                 "requests",
					Version:              "2.22.0",
					License:              "Apache 2.0",
					Platform:             "UNKNOWN",
					Author:               "Kenneth Reitz",
					AuthorEmail:          "me@kennethreitz.org",
					SitePackagesRootPath: "test-fixtures",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := source.NewMockResolverForPaths(test.fixtures...)

			locations, err := resolver.FilesByPath(test.fixtures...)
			if err != nil {
				t.Fatal(err)
			}

			test.expectedPackage.Locations = source.NewLocationSet(locations...)

			actual, _, err := NewPythonPackageCataloger().Catalog(resolver)
			if err != nil {
				t.Fatalf("failed to catalog python package: %+v", err)
			}

			if len(actual) != 1 {
				t.Fatalf("unexpected number of packages: %d", len(actual))
			}

			for _, d := range deep.Equal(actual[0], test.expectedPackage) {
				t.Errorf("diff: %+v", d)
			}
		})
	}
}

func TestIgnorePackage(t *testing.T) {
	tests := []struct {
		MetadataFixture string
	}{
		{
			MetadataFixture: "test-fixtures/Python-2.7.egg-info",
		},
	}

	for _, test := range tests {
		t.Run(test.MetadataFixture, func(t *testing.T) {
			resolver := source.NewMockResolverForPaths(test.MetadataFixture)

			actual, _, err := NewPythonPackageCataloger().Catalog(resolver)
			if err != nil {
				t.Fatalf("failed to catalog python package: %+v", err)
			}

			if len(actual) != 0 {
				t.Fatalf("Expected 0 packages but found: %d", len(actual))
			}
		})
	}
}
