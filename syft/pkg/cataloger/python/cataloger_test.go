package python

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_PackageCataloger(t *testing.T) {
	tests := []struct {
		name            string
		fixtures        []string
		expectedPackage pkg.Package
	}{
		{
			name:     "egg-file-no-version",
			fixtures: []string{"test-fixtures/no-version-py3.8.egg-info"},
			expectedPackage: pkg.Package{
				Name:         "no-version",
				PURL:         "pkg:pypi/no-version",
				Type:         pkg.PythonPkg,
				Language:     pkg.Python,
				FoundBy:      "python-package-cataloger",
				MetadataType: pkg.PythonPackageMetadataType,
				Metadata: pkg.PythonPackageMetadata{
					Name:                 "no-version",
					SitePackagesRootPath: "test-fixtures",
				},
			},
		},
		{
			name: "egg-info directory",
			fixtures: []string{
				"test-fixtures/egg-info/PKG-INFO",
				"test-fixtures/egg-info/RECORD",
				"test-fixtures/egg-info/top_level.txt",
			},
			expectedPackage: pkg.Package{
				Name:     "requests",
				Version:  "2.22.0",
				PURL:     "pkg:pypi/requests@2.22.0",
				Type:     pkg.PythonPkg,
				Language: pkg.Python,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocations("Apache 2.0", file.NewLocation("test-fixtures/egg-info/PKG-INFO")),
				),
				FoundBy:      "python-package-cataloger",
				MetadataType: pkg.PythonPackageMetadataType,
				Metadata: pkg.PythonPackageMetadata{
					Name:                 "requests",
					Version:              "2.22.0",
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
				Name:     "Pygments",
				Version:  "2.6.1",
				PURL:     "pkg:pypi/Pygments@2.6.1?vcs_url=git+https://github.com/python-test/test.git%40aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Type:     pkg.PythonPkg,
				Language: pkg.Python,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocations("BSD License", file.NewLocation("test-fixtures/dist-info/METADATA")),
				),
				FoundBy:      "python-package-cataloger",
				MetadataType: pkg.PythonPackageMetadataType,
				Metadata: pkg.PythonPackageMetadata{
					Name:                 "Pygments",
					Version:              "2.6.1",
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
			name: "malformed-record",
			fixtures: []string{
				"test-fixtures/malformed-record/dist-info/METADATA",
				"test-fixtures/malformed-record/dist-info/RECORD",
			},
			expectedPackage: pkg.Package{
				Name:     "Pygments",
				Version:  "2.6.1",
				PURL:     "pkg:pypi/Pygments@2.6.1",
				Type:     pkg.PythonPkg,
				Language: pkg.Python,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocations("BSD License", file.NewLocation("test-fixtures/malformed-record/dist-info/METADATA")),
				),
				FoundBy:      "python-package-cataloger",
				MetadataType: pkg.PythonPackageMetadataType,
				Metadata: pkg.PythonPackageMetadata{
					Name:                 "Pygments",
					Version:              "2.6.1",
					Platform:             "any",
					Author:               "Georg Brandl",
					AuthorEmail:          "georg@python.org",
					SitePackagesRootPath: "test-fixtures/malformed-record",
					Files: []pkg.PythonFileRecord{
						{Path: "flask/json/tag.py", Digest: &pkg.PythonFileDigest{"sha256", "9ehzrmt5k7hxf7ZEK0NOs3swvQyU9fWNe-pnYe69N60"}, Size: "8223"},
						{Path: "../../Scripts/flask.exe", Digest: &pkg.PythonFileDigest{"sha256", "mPrbVeZCDX20himZ_bRai1nCs_tgr7jHIOGZlcgn-T4"}, Size: "93063"},
						{Path: "../../Scripts/flask.exe", Size: "89470", Digest: &pkg.PythonFileDigest{"sha256", "jvqh4N3qOqXLlq40i6ZOLCY9tAOwfwdzIpLDYhRjoqQ"}},
						{Path: "Flask-1.0.2.dist-info/INSTALLER", Size: "4", Digest: &pkg.PythonFileDigest{"sha256", "zuuue4knoyJ-UwPPXg8fezS7VCrXJQrAP7zeNuwvFQg"}},
					},
				},
			},
		},
		{
			// in cases where the metadata file is available and the record is not we should still record there is a package
			// additionally empty top_level.txt files should not result in an error
			name:     "partial dist-info directory",
			fixtures: []string{"test-fixtures/partial.dist-info/METADATA"},
			expectedPackage: pkg.Package{
				Name:     "Pygments",
				Version:  "2.6.1",
				PURL:     "pkg:pypi/Pygments@2.6.1",
				Type:     pkg.PythonPkg,
				Language: pkg.Python,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocations("BSD License", file.NewLocation("test-fixtures/partial.dist-info/METADATA")),
				),
				FoundBy:      "python-package-cataloger",
				MetadataType: pkg.PythonPackageMetadataType,
				Metadata: pkg.PythonPackageMetadata{
					Name:                 "Pygments",
					Version:              "2.6.1",
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
				Name:     "requests",
				Version:  "2.22.0",
				PURL:     "pkg:pypi/requests@2.22.0",
				Type:     pkg.PythonPkg,
				Language: pkg.Python,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocations("Apache 2.0", file.NewLocation("test-fixtures/test.egg-info")),
				),
				FoundBy:      "python-package-cataloger",
				MetadataType: pkg.PythonPackageMetadataType,
				Metadata: pkg.PythonPackageMetadata{
					Name:                 "requests",
					Version:              "2.22.0",
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
			resolver := file.NewMockResolverForPaths(test.fixtures...)

			locations, err := resolver.FilesByPath(test.fixtures...)
			require.NoError(t, err)

			test.expectedPackage.Locations = file.NewLocationSet(locations...)

			pkgtest.NewCatalogTester().
				WithResolver(resolver).
				Expects([]pkg.Package{test.expectedPackage}, nil).
				TestCataloger(t, NewPythonPackageCataloger())
		})
	}
}

func Test_PackageCataloger_IgnorePackage(t *testing.T) {
	tests := []struct {
		MetadataFixture string
	}{
		{
			MetadataFixture: "test-fixtures/Python-2.7.egg-info",
		},
		{
			MetadataFixture: "test-fixtures/empty-1.0.0-py3.8.egg-info",
		},
	}

	for _, test := range tests {
		t.Run(test.MetadataFixture, func(t *testing.T) {
			resolver := file.NewMockResolverForPaths(test.MetadataFixture)

			actual, _, err := NewPythonPackageCataloger().Catalog(resolver)
			require.NoError(t, err)

			if len(actual) != 0 {
				t.Fatalf("Expected 0 packages but found: %d", len(actual))
			}
		})
	}
}

func Test_IndexCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain index files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"src/requirements.txt",
				"src/extra-requirements.txt",
				"src/requirements-dev.txt",
				"src/1-requirements-dev.txt",
				"src/setup.py",
				"src/poetry.lock",
				"src/Pipfile.lock",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewPythonIndexCataloger(DefaultCatalogerConfig()))
		})
	}
}

func Test_PackageCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain index files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"site-packages/x.dist-info/METADATA",
				"site-packages/y.egg-info/PKG-INFO",
				"site-packages/z.egg-info",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewPythonPackageCataloger())
		})
	}
}
