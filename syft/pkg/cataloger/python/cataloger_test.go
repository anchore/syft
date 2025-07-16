package python

import (
	"context"
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_PackageCataloger(t *testing.T) {
	ctx := context.TODO()
	tests := []struct {
		name             string
		fixture          string
		expectedPackages []pkg.Package
	}{
		{
			name:    "egg-file-no-version",
			fixture: "test-fixtures/site-packages/no-version",
			expectedPackages: []pkg.Package{
				{
					Name:      "no-version",
					Locations: file.NewLocationSet(file.NewLocation("no-version-py3.8.egg-info")),
					PURL:      "pkg:pypi/no-version",
					Type:      pkg.PythonPkg,
					Language:  pkg.Python,
					FoundBy:   "python-installed-package-cataloger",
					Metadata: pkg.PythonPackage{
						Name:                 "no-version",
						SitePackagesRootPath: ".", // requires scanning the grandparent directory to get a valid path
					},
				},
			},
		},
		{
			name:    "dist-info+egg-info site-packages directory",
			fixture: "test-fixtures/site-packages/nested",
			expectedPackages: []pkg.Package{
				{
					Name:     "pygments",
					Version:  "2.6.1",
					PURL:     "pkg:pypi/pygments@2.6.1?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fpython-test%2Ftest.git%40aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					Type:     pkg.PythonPkg,
					Language: pkg.Python,
					Locations: file.NewLocationSet(
						file.NewLocation("dist-name/dist-info/METADATA"),
						file.NewLocation("dist-name/dist-info/RECORD"),
						file.NewLocation("dist-name/dist-info/direct_url.json"),
						file.NewLocation("dist-name/dist-info/top_level.txt"),
					),
					Licenses: pkg.NewLicenseSet(
						// here we only used the license that was declared in the METADATA file, we did not go searching for other licenses
						// this is the better source of truth when there is no explicit LicenseFile given
						pkg.NewLicenseFromLocationsWithContext(ctx, "BSD License", file.NewLocation("dist-name/dist-info/METADATA")),
					),
					FoundBy: "python-installed-package-cataloger",
					Metadata: pkg.PythonPackage{
						Name:                 "Pygments",
						Version:              "2.6.1",
						Platform:             "any",
						Author:               "Georg Brandl",
						AuthorEmail:          "georg@python.org",
						SitePackagesRootPath: "dist-name",
						Files: []pkg.PythonFileRecord{
							{Path: "../../../bin/pygmentize", Digest: &pkg.PythonFileDigest{"sha256", "dDhv_U2jiCpmFQwIRHpFRLAHUO4R1jIJPEvT_QYTFp8"}, Size: "220"},
							{Path: "Pygments-2.6.1.dist-info/AUTHORS", Digest: &pkg.PythonFileDigest{"sha256", "PVpa2_Oku6BGuiUvutvuPnWGpzxqFy2I8-NIrqCvqUY"}, Size: "8449"},
							{Path: "Pygments-2.6.1.dist-info/LICENSE.txt", Digest: &pkg.PythonFileDigest{Algorithm: "sha256", Value: "utiUvpzxqFPVpvuPnWG2_Oku6BGuay2I8-NIrqCvqUY"}, Size: "8449"},
							{Path: "Pygments-2.6.1.dist-info/RECORD"},
							{Path: "pygments/__pycache__/__init__.cpython-38.pyc"},
							{Path: "pygments/util.py", Digest: &pkg.PythonFileDigest{"sha256", "586xXHiJGGZxqk5PMBu3vBhE68DLuAe5MBARWrSPGxA"}, Size: "10778"},

							{Path: "pygments/x_util.py", Digest: &pkg.PythonFileDigest{"sha256", "qpzzsOW31KT955agi-7NS--90I0iNiJCyLJQnRCHgKI="}, Size: "10778"},
						},
						TopLevelPackages: []string{"pygments", "something_else"},
						DirectURLOrigin:  &pkg.PythonDirectURLOriginInfo{URL: "https://github.com/python-test/test.git", VCS: "git", CommitID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
						RequiresPython:   ">=3.5",
						RequiresDist:     []string{"soupsieve (>1.2)", "html5lib ; extra == 'html5lib'", "lxml ; extra == 'lxml'"},
						ProvidesExtra:    []string{"html5lib", "lxml"},
					},
				},
				{
					Name:     "requests",
					Version:  "2.22.0",
					PURL:     "pkg:pypi/requests@2.22.0",
					Type:     pkg.PythonPkg,
					Language: pkg.Python,
					Locations: file.NewLocationSet(
						file.NewLocation("egg-name/egg-info/PKG-INFO"),
						file.NewLocation("egg-name/egg-info/RECORD"),
						file.NewLocation("egg-name/egg-info/top_level.txt"),
					),
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromLocationsWithContext(ctx, "Apache 2.0", file.NewLocation("egg-name/egg-info/PKG-INFO")),
					),
					FoundBy: "python-installed-package-cataloger",
					Metadata: pkg.PythonPackage{
						Name:                 "requests",
						Version:              "2.22.0",
						Platform:             "UNKNOWN",
						Author:               "Kenneth Reitz",
						AuthorEmail:          "me@kennethreitz.org",
						SitePackagesRootPath: "egg-name",
						Files: []pkg.PythonFileRecord{
							{Path: "requests-2.22.0.dist-info/INSTALLER", Digest: &pkg.PythonFileDigest{"sha256", "zuuue4knoyJ-UwPPXg8fezS7VCrXJQrAP7zeNuwvFQg"}, Size: "4"},
							{Path: "requests/__init__.py", Digest: &pkg.PythonFileDigest{"sha256", "PnKCgjcTq44LaAMzB-7--B2FdewRrE8F_vjZeaG9NhA"}, Size: "3921"},
							{Path: "requests/__pycache__/__version__.cpython-38.pyc"},
							{Path: "requests/__pycache__/utils.cpython-38.pyc"},
							{Path: "requests/__version__.py", Digest: &pkg.PythonFileDigest{"sha256", "Bm-GFstQaFezsFlnmEMrJDe8JNROz9n2XXYtODdvjjc"}, Size: "436"},
							{Path: "requests/utils.py", Digest: &pkg.PythonFileDigest{"sha256", "LtPJ1db6mJff2TJSJWKi7rBpzjPS3mSOrjC9zRhoD3A"}, Size: "30049"},
						},
						TopLevelPackages: []string{"requests"},
						RequiresPython:   ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*",
						ProvidesExtra:    []string{"security", "socks"},
					},
				},
			},
		},
		{
			name:    "DIST-INFO+EGG-INFO site-packages directory (case insensitive)",
			fixture: "test-fixtures/site-packages/uppercase",
			expectedPackages: []pkg.Package{
				{
					Name:     "pygments",
					Version:  "2.6.1",
					PURL:     "pkg:pypi/pygments@2.6.1?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fpython-test%2Ftest.git%40aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					Type:     pkg.PythonPkg,
					Language: pkg.Python,
					Locations: file.NewLocationSet(
						file.NewLocation("dist-name/DIST-INFO/METADATA"),
						file.NewLocation("dist-name/DIST-INFO/RECORD"),
						file.NewLocation("dist-name/DIST-INFO/direct_url.json"),
						file.NewLocation("dist-name/DIST-INFO/top_level.txt"),
					),
					Licenses: pkg.NewLicenseSet(
						// here we only used the license that was declared in the METADATA file, we did not go searching for other licenses
						// this is the better source of truth when there is no explicit LicenseFile given
						pkg.NewLicenseFromLocationsWithContext(ctx, "BSD License", file.NewLocation("dist-name/DIST-INFO/METADATA")),
					),
					FoundBy: "python-installed-package-cataloger",
					Metadata: pkg.PythonPackage{
						Name:                 "Pygments",
						Version:              "2.6.1",
						Platform:             "any",
						Author:               "Georg Brandl",
						AuthorEmail:          "georg@python.org",
						SitePackagesRootPath: "dist-name",
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
						RequiresPython:   ">=3.5",
					},
				},
				{
					Name:     "requests",
					Version:  "2.22.0",
					PURL:     "pkg:pypi/requests@2.22.0",
					Type:     pkg.PythonPkg,
					Language: pkg.Python,
					Locations: file.NewLocationSet(
						file.NewLocation("egg-name/EGG-INFO/PKG-INFO"),
						file.NewLocation("egg-name/EGG-INFO/RECORD"),
						file.NewLocation("egg-name/EGG-INFO/top_level.txt"),
					),
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromLocationsWithContext(ctx, "Apache 2.0", file.NewLocation("egg-name/EGG-INFO/PKG-INFO")),
					),
					FoundBy: "python-installed-package-cataloger",
					Metadata: pkg.PythonPackage{
						Name:                 "requests",
						Version:              "2.22.0",
						Platform:             "UNKNOWN",
						Author:               "Kenneth Reitz",
						AuthorEmail:          "me@kennethreitz.org",
						SitePackagesRootPath: "egg-name",
						Files: []pkg.PythonFileRecord{
							{Path: "requests-2.22.0.dist-info/INSTALLER", Digest: &pkg.PythonFileDigest{"sha256", "zuuue4knoyJ-UwPPXg8fezS7VCrXJQrAP7zeNuwvFQg"}, Size: "4"},
							{Path: "requests/__init__.py", Digest: &pkg.PythonFileDigest{"sha256", "PnKCgjcTq44LaAMzB-7--B2FdewRrE8F_vjZeaG9NhA"}, Size: "3921"},
							{Path: "requests/__pycache__/__version__.cpython-38.pyc"},
							{Path: "requests/__pycache__/utils.cpython-38.pyc"},
							{Path: "requests/__version__.py", Digest: &pkg.PythonFileDigest{"sha256", "Bm-GFstQaFezsFlnmEMrJDe8JNROz9n2XXYtODdvjjc"}, Size: "436"},
							{Path: "requests/utils.py", Digest: &pkg.PythonFileDigest{"sha256", "LtPJ1db6mJff2TJSJWKi7rBpzjPS3mSOrjC9zRhoD3A"}, Size: "30049"},
						},
						TopLevelPackages: []string{"requests"},
						RequiresPython:   ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*",
						ProvidesExtra:    []string{"security", "socks"},
					},
				},
			},
		},
		{
			name:    "detect licenses",
			fixture: "test-fixtures/site-packages/license",
			expectedPackages: []pkg.Package{
				{
					Name:     "pygments",
					Version:  "2.6.1",
					PURL:     "pkg:pypi/pygments@2.6.1?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fpython-test%2Ftest.git%40aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					Type:     pkg.PythonPkg,
					Language: pkg.Python,
					Locations: file.NewLocationSet(
						file.NewLocation("with-license-file-declared.dist-info/METADATA"), // the LicenseFile is declared in the METADATA file
						file.NewLocation("with-license-file-declared.dist-info/RECORD"),
						file.NewLocation("with-license-file-declared.dist-info/top_level.txt"),
						file.NewLocation("with-license-file-declared.dist-info/direct_url.json"),
					),
					Licenses: pkg.NewLicenseSet(
						pkg.License{
							Value:          "BSD-3-Clause",
							SPDXExpression: "BSD-3-Clause",
							Type:           "concluded",
							Contents:       mustContentsFromLocation(t, "test-fixtures/site-packages/license/with-license-file-declared.dist-info/LICENSE.txt", 0, 1475),
							// we read the path from the LicenseFile field in the METADATA file, then read the license file directly
							Locations: file.NewLocationSet(file.NewLocation("with-license-file-declared.dist-info/LICENSE.txt")),
						},
					),
					FoundBy: "python-installed-package-cataloger",
					Metadata: pkg.PythonPackage{
						Name:                 "Pygments",
						Version:              "2.6.1",
						Platform:             "any",
						Author:               "Georg Brandl",
						AuthorEmail:          "georg@python.org",
						SitePackagesRootPath: ".",
						Files: []pkg.PythonFileRecord{
							{Path: "../../../bin/pygmentize", Digest: &pkg.PythonFileDigest{"sha256", "dDhv_U2jiCpmFQwIRHpFRLAHUO4R1jIJPEvT_QYTFp8"}, Size: "220"},
							{Path: "with-license-file-declared.dist-info/AUTHORS", Digest: &pkg.PythonFileDigest{"sha256", "PVpa2_Oku6BGuiUvutvuPnWGpzxqFy2I8-NIrqCvqUY"}, Size: "8449"},
							{Path: "with-license-file-declared.dist-info/LICENSE.txt", Digest: &pkg.PythonFileDigest{Algorithm: "sha256", Value: "utiUvpzxqFPVpvuPnWG2_Oku6BGuay2I8-NIrqCvqUY"}, Size: "8449"},
							{Path: "with-license-file-declared.dist-info/RECORD"},
							{Path: "pygments/__pycache__/__init__.cpython-38.pyc"},
							{Path: "pygments/util.py", Digest: &pkg.PythonFileDigest{"sha256", "586xXHiJGGZxqk5PMBu3vBhE68DLuAe5MBARWrSPGxA"}, Size: "10778"},

							{Path: "pygments/x_util.py", Digest: &pkg.PythonFileDigest{"sha256", "qpzzsOW31KT955agi-7NS--90I0iNiJCyLJQnRCHgKI="}, Size: "10778"},
						},
						TopLevelPackages: []string{"pygments", "something_else"},
						DirectURLOrigin:  &pkg.PythonDirectURLOriginInfo{URL: "https://github.com/python-test/test.git", VCS: "git", CommitID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
						RequiresPython:   ">=3.5",
						RequiresDist:     []string{"soupsieve (>1.2)", "html5lib ; extra == 'html5lib'", "lxml ; extra == 'lxml'"},
						ProvidesExtra:    []string{"html5lib", "lxml"},
					},
				},
				{
					Name:     "pygments",
					Version:  "2.6.1",
					PURL:     "pkg:pypi/pygments@2.6.1?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fpython-test%2Ftest.git%40aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					Type:     pkg.PythonPkg,
					Language: pkg.Python,
					Locations: file.NewLocationSet(
						file.NewLocation("without-license-file-declared.dist-info/METADATA"), // the LicenseFile is declared in the METADATA file
						file.NewLocation("without-license-file-declared.dist-info/RECORD"),
						file.NewLocation("without-license-file-declared.dist-info/top_level.txt"),
						file.NewLocation("without-license-file-declared.dist-info/direct_url.json"),
					),
					Licenses: pkg.NewLicenseSet(
						pkg.License{
							Value:          "BSD-3-Clause",
							SPDXExpression: "BSD-3-Clause",
							Type:           "concluded",
							Contents:       mustContentsFromLocation(t, "test-fixtures/site-packages/license/with-license-file-declared.dist-info/LICENSE.txt", 0, 1475),
							Locations:      file.NewLocationSet(file.NewLocation("without-license-file-declared.dist-info/LICENSE.txt")),
						},
					),
					FoundBy: "python-installed-package-cataloger",
					Metadata: pkg.PythonPackage{
						Name:                 "Pygments",
						Version:              "2.6.1",
						Platform:             "any",
						Author:               "Georg Brandl",
						AuthorEmail:          "georg@python.org",
						SitePackagesRootPath: ".",
						Files: []pkg.PythonFileRecord{
							{Path: "../../../bin/pygmentize", Digest: &pkg.PythonFileDigest{"sha256", "dDhv_U2jiCpmFQwIRHpFRLAHUO4R1jIJPEvT_QYTFp8"}, Size: "220"},
							{Path: "without-license-file-declared.dist-info/AUTHORS", Digest: &pkg.PythonFileDigest{"sha256", "PVpa2_Oku6BGuiUvutvuPnWGpzxqFy2I8-NIrqCvqUY"}, Size: "8449"},
							{Path: "without-license-file-declared.dist-info/LICENSE.txt", Digest: &pkg.PythonFileDigest{Algorithm: "sha256", Value: "utiUvpzxqFPVpvuPnWG2_Oku6BGuay2I8-NIrqCvqUY"}, Size: "8449"},
							{Path: "without-license-file-declared.dist-info/RECORD"},
							{Path: "pygments/__pycache__/__init__.cpython-38.pyc"},
							{Path: "pygments/util.py", Digest: &pkg.PythonFileDigest{"sha256", "586xXHiJGGZxqk5PMBu3vBhE68DLuAe5MBARWrSPGxA"}, Size: "10778"},

							{Path: "pygments/x_util.py", Digest: &pkg.PythonFileDigest{"sha256", "qpzzsOW31KT955agi-7NS--90I0iNiJCyLJQnRCHgKI="}, Size: "10778"},
						},
						TopLevelPackages: []string{"pygments", "something_else"},
						DirectURLOrigin:  &pkg.PythonDirectURLOriginInfo{URL: "https://github.com/python-test/test.git", VCS: "git", CommitID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
						RequiresPython:   ">=3.5",
						RequiresDist:     []string{"soupsieve (>1.2)", "html5lib ; extra == 'html5lib'", "lxml ; extra == 'lxml'"},
						ProvidesExtra:    []string{"html5lib", "lxml"},
					},
				},
			},
		},
		{
			name:    "malformed-record",
			fixture: "test-fixtures/site-packages/malformed-record",
			expectedPackages: []pkg.Package{
				{
					Name:     "pygments",
					Version:  "2.6.1",
					PURL:     "pkg:pypi/pygments@2.6.1",
					Type:     pkg.PythonPkg,
					Language: pkg.Python,
					Locations: file.NewLocationSet(
						file.NewLocation("dist-info/METADATA"),
						file.NewLocation("dist-info/RECORD"),
					),
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromLocationsWithContext(ctx, "BSD License", file.NewLocation("dist-info/METADATA")),
					),
					FoundBy: "python-installed-package-cataloger",
					Metadata: pkg.PythonPackage{
						Name:                 "Pygments",
						Version:              "2.6.1",
						Platform:             "any",
						Author:               "Georg Brandl",
						AuthorEmail:          "georg@python.org",
						SitePackagesRootPath: ".",
						Files: []pkg.PythonFileRecord{
							{Path: "flask/json/tag.py", Digest: &pkg.PythonFileDigest{"sha256", "9ehzrmt5k7hxf7ZEK0NOs3swvQyU9fWNe-pnYe69N60"}, Size: "8223"},
							{Path: "../../Scripts/flask.exe", Digest: &pkg.PythonFileDigest{"sha256", "mPrbVeZCDX20himZ_bRai1nCs_tgr7jHIOGZlcgn-T4"}, Size: "93063"},
							{Path: "../../Scripts/flask.exe", Size: "89470", Digest: &pkg.PythonFileDigest{"sha256", "jvqh4N3qOqXLlq40i6ZOLCY9tAOwfwdzIpLDYhRjoqQ"}},
							{Path: "Flask-1.0.2.dist-info/INSTALLER", Size: "4", Digest: &pkg.PythonFileDigest{"sha256", "zuuue4knoyJ-UwPPXg8fezS7VCrXJQrAP7zeNuwvFQg"}},
						},
						RequiresPython: ">=3.5",
					},
				},
			},
		},
		{
			// in cases where the metadata file is available and the record is not we should still record there is a package
			// additionally empty top_level.txt files should not result in an error
			name:    "partial dist-info directory",
			fixture: "test-fixtures/site-packages/partial.dist-info",
			expectedPackages: []pkg.Package{
				{
					Name:     "pygments",
					Version:  "2.6.1",
					PURL:     "pkg:pypi/pygments@2.6.1",
					Type:     pkg.PythonPkg,
					Language: pkg.Python,
					Locations: file.NewLocationSet(
						file.NewLocation("METADATA"),
					),
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromLocationsWithContext(ctx, "BSD License", file.NewLocation("METADATA")),
					),
					FoundBy: "python-installed-package-cataloger",
					Metadata: pkg.PythonPackage{
						Name:                 "Pygments",
						Version:              "2.6.1",
						Platform:             "any",
						Author:               "Georg Brandl",
						AuthorEmail:          "georg@python.org",
						SitePackagesRootPath: ".",
						RequiresPython:       ">=3.5",
					},
				},
			},
		},
		{
			name:    "egg-info regular file",
			fixture: "test-fixtures/site-packages/test",
			expectedPackages: []pkg.Package{
				{
					Name:     "requests",
					Version:  "2.22.0",
					PURL:     "pkg:pypi/requests@2.22.0",
					Type:     pkg.PythonPkg,
					Language: pkg.Python,
					Locations: file.NewLocationSet(
						file.NewLocation("test.egg-info"),
					),
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromLocationsWithContext(ctx, "Apache 2.0", file.NewLocation("test.egg-info")),
					),
					FoundBy: "python-installed-package-cataloger",
					Metadata: pkg.PythonPackage{
						Name:                 "requests",
						Version:              "2.22.0",
						Platform:             "UNKNOWN",
						Author:               "Kenneth Reitz",
						AuthorEmail:          "me@kennethreitz.org",
						SitePackagesRootPath: ".",
						RequiresPython:       ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*",
						ProvidesExtra:        []string{"security", "socks"},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			(pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				Expects(test.expectedPackages, nil).
				TestCataloger(t, NewInstalledPackageCataloger()))
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

			actual, _, err := NewInstalledPackageCataloger().Catalog(pkgtest.Context(), resolver)
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
				"src/uv.lock",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewPackageCataloger(DefaultCatalogerConfig()))
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
				"site-packages/v.DIST-INFO/METADATA",
				"site-packages/w.EGG-INFO/PKG-INFO",
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
				IgnoreUnfulfilledPathResponses("**/pyvenv.cfg").
				TestCataloger(t, NewInstalledPackageCataloger())
		})
	}
}

func Test_PackageCataloger_Relationships(t *testing.T) {
	tests := []struct {
		name                  string
		fixture               string
		expectedRelationships []string
	}{
		{
			name:                  "poetry - no dependencies",
			fixture:               "test-fixtures/poetry/dev-deps",
			expectedRelationships: nil,
		},
		{
			name:    "poetry - simple dependencies",
			fixture: "test-fixtures/poetry/simple-deps",
			expectedRelationships: []string{
				"certifi @ 2024.2.2 (.) [dependency-of] requests @ 2.32.2 (.)",
				"charset-normalizer @ 3.3.2 (.) [dependency-of] requests @ 2.32.2 (.)",
				"idna @ 3.7 (.) [dependency-of] requests @ 2.32.2 (.)",
				"urllib3 @ 2.2.1 (.) [dependency-of] requests @ 2.32.2 (.)",
			},
		},
		{
			name:    "poetry - multiple extras",
			fixture: "test-fixtures/poetry/multiple-extras",
			expectedRelationships: []string{
				"anyio @ 4.3.0 (.) [dependency-of] anyio @ 4.3.0 (.)",
				"anyio @ 4.3.0 (.) [dependency-of] httpcore @ 1.0.5 (.)",
				"anyio @ 4.3.0 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"brotli @ 1.1.0 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"brotlicffi @ 1.1.0.0 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"certifi @ 2024.2.2 (.) [dependency-of] httpcore @ 1.0.5 (.)",
				"certifi @ 2024.2.2 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"cffi @ 1.16.0 (.) [dependency-of] brotlicffi @ 1.1.0.0 (.)",
				"h11 @ 0.14.0 (.) [dependency-of] httpcore @ 1.0.5 (.)",
				"h2 @ 4.1.0 (.) [dependency-of] httpcore @ 1.0.5 (.)",
				"h2 @ 4.1.0 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"hpack @ 4.0.0 (.) [dependency-of] h2 @ 4.1.0 (.)",
				"httpcore @ 1.0.5 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"hyperframe @ 6.0.1 (.) [dependency-of] h2 @ 4.1.0 (.)",
				"idna @ 3.7 (.) [dependency-of] anyio @ 4.3.0 (.)",
				"idna @ 3.7 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"pycparser @ 2.22 (.) [dependency-of] cffi @ 1.16.0 (.)",
				"sniffio @ 1.3.1 (.) [dependency-of] anyio @ 4.3.0 (.)",
				"sniffio @ 1.3.1 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"socksio @ 1.0.0 (.) [dependency-of] httpcore @ 1.0.5 (.)",
				"socksio @ 1.0.0 (.) [dependency-of] httpx @ 0.27.0 (.)",
			},
		},
		{
			name:    "poetry - nested extras",
			fixture: "test-fixtures/poetry/nested-extras",
			expectedRelationships: []string{
				"annotated-types @ 0.7.0 (.) [dependency-of] pydantic @ 2.7.1 (.)",
				"anyio @ 4.3.0 (.) [dependency-of] anyio @ 4.3.0 (.)",
				"anyio @ 4.3.0 (.) [dependency-of] httpcore @ 1.0.5 (.)",
				"anyio @ 4.3.0 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"anyio @ 4.3.0 (.) [dependency-of] starlette @ 0.37.2 (.)",
				"anyio @ 4.3.0 (.) [dependency-of] watchfiles @ 0.21.0 (.)",
				"certifi @ 2024.2.2 (.) [dependency-of] httpcore @ 1.0.5 (.)",
				"certifi @ 2024.2.2 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"click @ 8.1.7 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"click @ 8.1.7 (.) [dependency-of] python-dotenv @ 1.0.1 (.)",
				"click @ 8.1.7 (.) [dependency-of] typer @ 0.12.3 (.)",
				"click @ 8.1.7 (.) [dependency-of] uvicorn @ 0.29.0 (.)",
				"colorama @ 0.4.6 (.) [dependency-of] click @ 8.1.7 (.)",
				"colorama @ 0.4.6 (.) [dependency-of] pygments @ 2.18.0 (.)",
				"colorama @ 0.4.6 (.) [dependency-of] uvicorn @ 0.29.0 (.)", // proof of uvicorn[standard]
				"dnspython @ 2.6.1 (.) [dependency-of] email-validator @ 2.1.1 (.)",
				"email-validator @ 2.1.1 (.) [dependency-of] pydantic @ 2.7.1 (.)",
				"fastapi @ 0.111.0 (.) [dependency-of] fastapi-cli @ 0.0.4 (.)",
				"fastapi-cli @ 0.0.4 (.) [dependency-of] fastapi @ 0.111.0 (.)",
				"h11 @ 0.14.0 (.) [dependency-of] httpcore @ 1.0.5 (.)",
				"h11 @ 0.14.0 (.) [dependency-of] uvicorn @ 0.29.0 (.)",
				"httpcore @ 1.0.5 (.) [dependency-of] dnspython @ 2.6.1 (.)",
				"httpcore @ 1.0.5 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"httptools @ 0.6.1 (.) [dependency-of] uvicorn @ 0.29.0 (.)", // proof of uvicorn[standard]
				"httpx @ 0.27.0 (.) [dependency-of] dnspython @ 2.6.1 (.)",
				"httpx @ 0.27.0 (.) [dependency-of] fastapi @ 0.111.0 (.)",
				"httpx @ 0.27.0 (.) [dependency-of] starlette @ 0.37.2 (.)",
				"idna @ 3.7 (.) [dependency-of] anyio @ 4.3.0 (.)",
				"idna @ 3.7 (.) [dependency-of] dnspython @ 2.6.1 (.)",
				"idna @ 3.7 (.) [dependency-of] email-validator @ 2.1.1 (.)",
				"idna @ 3.7 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"itsdangerous @ 2.2.0 (.) [dependency-of] fastapi @ 0.111.0 (.)",
				"itsdangerous @ 2.2.0 (.) [dependency-of] starlette @ 0.37.2 (.)",
				"jinja2 @ 3.1.4 (.) [dependency-of] fastapi @ 0.111.0 (.)",
				"jinja2 @ 3.1.4 (.) [dependency-of] starlette @ 0.37.2 (.)",
				"markdown-it-py @ 3.0.0 (.) [dependency-of] rich @ 13.7.1 (.)",
				"mdurl @ 0.1.2 (.) [dependency-of] markdown-it-py @ 3.0.0 (.)",
				"orjson @ 3.10.3 (.) [dependency-of] fastapi @ 0.111.0 (.)",
				"pydantic @ 2.7.1 (.) [dependency-of] fastapi @ 0.111.0 (.)",
				"pydantic @ 2.7.1 (.) [dependency-of] pydantic-extra-types @ 2.7.0 (.)",
				"pydantic @ 2.7.1 (.) [dependency-of] pydantic-settings @ 2.2.1 (.)",
				"pydantic-core @ 2.18.2 (.) [dependency-of] pydantic @ 2.7.1 (.)",
				"pydantic-extra-types @ 2.7.0 (.) [dependency-of] fastapi @ 0.111.0 (.)",
				"pydantic-settings @ 2.2.1 (.) [dependency-of] fastapi @ 0.111.0 (.)",
				"pygments @ 2.18.0 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"pygments @ 2.18.0 (.) [dependency-of] rich @ 13.7.1 (.)",
				"python-dotenv @ 1.0.1 (.) [dependency-of] pydantic-settings @ 2.2.1 (.)",
				"python-dotenv @ 1.0.1 (.) [dependency-of] uvicorn @ 0.29.0 (.)", // proof of uvicorn[standard]
				"python-multipart @ 0.0.9 (.) [dependency-of] fastapi @ 0.111.0 (.)",
				"python-multipart @ 0.0.9 (.) [dependency-of] starlette @ 0.37.2 (.)",
				"pyyaml @ 6.0.1 (.) [dependency-of] fastapi @ 0.111.0 (.)",
				"pyyaml @ 6.0.1 (.) [dependency-of] markdown-it-py @ 3.0.0 (.)",
				"pyyaml @ 6.0.1 (.) [dependency-of] pydantic-settings @ 2.2.1 (.)",
				"pyyaml @ 6.0.1 (.) [dependency-of] python-multipart @ 0.0.9 (.)",
				"pyyaml @ 6.0.1 (.) [dependency-of] starlette @ 0.37.2 (.)",
				"pyyaml @ 6.0.1 (.) [dependency-of] uvicorn @ 0.29.0 (.)", // proof of uvicorn[standard]
				"rich @ 13.7.1 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"rich @ 13.7.1 (.) [dependency-of] typer @ 0.12.3 (.)",
				"shellingham @ 1.5.4 (.) [dependency-of] typer @ 0.12.3 (.)",
				"sniffio @ 1.3.1 (.) [dependency-of] anyio @ 4.3.0 (.)",
				"sniffio @ 1.3.1 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"starlette @ 0.37.2 (.) [dependency-of] fastapi @ 0.111.0 (.)",
				"typer @ 0.12.3 (.) [dependency-of] fastapi-cli @ 0.0.4 (.)",
				"typing-extensions @ 4.12.0 (.) [dependency-of] fastapi @ 0.111.0 (.)",
				"typing-extensions @ 4.12.0 (.) [dependency-of] pydantic @ 2.7.1 (.)",
				"typing-extensions @ 4.12.0 (.) [dependency-of] pydantic-core @ 2.18.2 (.)",
				"typing-extensions @ 4.12.0 (.) [dependency-of] typer @ 0.12.3 (.)",
				"ujson @ 5.10.0 (.) [dependency-of] fastapi @ 0.111.0 (.)",
				"uvicorn @ 0.29.0 (.) [dependency-of] fastapi @ 0.111.0 (.)",
				"uvicorn @ 0.29.0 (.) [dependency-of] fastapi-cli @ 0.0.4 (.)",
				"uvloop @ 0.19.0 (.) [dependency-of] anyio @ 4.3.0 (.)",
				"uvloop @ 0.19.0 (.) [dependency-of] uvicorn @ 0.29.0 (.)",     // proof of uvicorn[standard]
				"watchfiles @ 0.21.0 (.) [dependency-of] uvicorn @ 0.29.0 (.)", // proof of uvicorn[standard]
				"websockets @ 12.0 (.) [dependency-of] uvicorn @ 0.29.0 (.)",   // proof of uvicorn[standard]
			},
		},
		{
			name:    "poetry - conflicting extras",
			fixture: "test-fixtures/poetry/conflicting-with-extras",
			expectedRelationships: []string{
				"anyio @ 4.3.0 (.) [dependency-of] anyio @ 4.3.0 (.)",
				"anyio @ 4.3.0 (.) [dependency-of] httpcore @ 1.0.5 (.)",
				"anyio @ 4.3.0 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"brotli @ 1.1.0 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"brotlicffi @ 1.1.0.0 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"certifi @ 2024.2.2 (.) [dependency-of] httpcore @ 1.0.5 (.)",
				"certifi @ 2024.2.2 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"cffi @ 1.16.0 (.) [dependency-of] brotlicffi @ 1.1.0.0 (.)",
				"colorama @ 0.4.6 (.) [dependency-of] rich @ 0.3.3 (.)",
				"h11 @ 0.14.0 (.) [dependency-of] httpcore @ 1.0.5 (.)",
				"h2 @ 4.1.0 (.) [dependency-of] httpcore @ 1.0.5 (.)",
				"h2 @ 4.1.0 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"hpack @ 4.0.0 (.) [dependency-of] h2 @ 4.1.0 (.)",
				"httpcore @ 1.0.5 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"hyperframe @ 6.0.1 (.) [dependency-of] h2 @ 4.1.0 (.)",
				"idna @ 3.7 (.) [dependency-of] anyio @ 4.3.0 (.)",
				"idna @ 3.7 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"pprintpp @ 0.4.0 (.) [dependency-of] rich @ 0.3.3 (.)",
				"pycparser @ 2.22 (.) [dependency-of] cffi @ 1.16.0 (.)",
				"sniffio @ 1.3.1 (.) [dependency-of] anyio @ 4.3.0 (.)",
				"sniffio @ 1.3.1 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"socksio @ 1.0.0 (.) [dependency-of] httpcore @ 1.0.5 (.)",
				"socksio @ 1.0.0 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"typing-extensions @ 3.10.0.2 (.) [dependency-of] rich @ 0.3.3 (.)",

				// ideally we should NOT see these dependencies. However, they are technically installed in the environment
				// and an import is present in httpx for each of these, so in theory they are actually dependencies even
				// though our pyproject.toml looks like this:
				//
				//     [tool.poetry.dependencies]
				//     python = "^3.11"
				//     httpx = {extras = ["brotli", "http2", "socks"], version = "^0.27.0"}
				//     pygments = "1.6"
				//     click = "<8"
				//     rich = "<10"
				//
				// note that pygments, click, and rich are installed outside of the allowable ranges for the given
				// httpx package version constraints, per the poetry.lock:
				//
				//     # for package httpx
				//     [package.extras]
				//     cli = ["click (==8.*)", "pygments (==2.*)", "rich (>=10,<14)"]
				//
				// note: the pyproject.toml and poetry.lock state are consistent with each other (just with
				// "poetry install" and "poetry lock", and nothing was forced!)
				"click @ 7.1.2 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"pygments @ 1.6 (.) [dependency-of] httpx @ 0.27.0 (.)",
				"rich @ 0.3.3 (.) [dependency-of] httpx @ 0.27.0 (.)",
			},
		},
		{
			name:    "uv - simple dependencies",
			fixture: "test-fixtures/uv/simple-deps",
			expectedRelationships: []string{
				"certifi @ 2025.1.31 (.) [dependency-of] requests @ 2.32.3 (.)",
				"charset-normalizer @ 3.4.1 (.) [dependency-of] requests @ 2.32.3 (.)",
				"idna @ 3.10 (.) [dependency-of] requests @ 2.32.3 (.)",
				"requests @ 2.32.3 (.) [dependency-of] testpkg @ 0.1.0 (.)",
				"urllib3 @ 2.3.0 (.) [dependency-of] requests @ 2.32.3 (.)",
			},
		},
		{
			name:    "uv - multiple extras",
			fixture: "test-fixtures/uv/multiple-extras",
			expectedRelationships: []string{
				"anyio @ 4.9.0 (.) [dependency-of] httpx @ 0.28.1 (.)",
				"brotli @ 1.1.0 (.) [dependency-of] httpx @ 0.28.1 (.)",
				"brotlicffi @ 1.1.0.0 (.) [dependency-of] httpx @ 0.28.1 (.)",
				"certifi @ 2025.1.31 (.) [dependency-of] httpcore @ 1.0.7 (.)",
				"certifi @ 2025.1.31 (.) [dependency-of] httpx @ 0.28.1 (.)",
				"cffi @ 1.17.1 (.) [dependency-of] brotlicffi @ 1.1.0.0 (.)",
				"h11 @ 0.14.0 (.) [dependency-of] httpcore @ 1.0.7 (.)",
				"h2 @ 4.2.0 (.) [dependency-of] httpx @ 0.28.1 (.)",
				"hpack @ 4.1.0 (.) [dependency-of] h2 @ 4.2.0 (.)",
				"httpcore @ 1.0.7 (.) [dependency-of] httpx @ 0.28.1 (.)",
				"httpx @ 0.28.1 (.) [dependency-of] testpkg @ 0.1.0 (.)",
				"hyperframe @ 6.1.0 (.) [dependency-of] h2 @ 4.2.0 (.)",
				"idna @ 3.10 (.) [dependency-of] anyio @ 4.9.0 (.)",
				"idna @ 3.10 (.) [dependency-of] httpx @ 0.28.1 (.)",
				"pycparser @ 2.22 (.) [dependency-of] cffi @ 1.17.1 (.)",
				"sniffio @ 1.3.1 (.) [dependency-of] anyio @ 4.9.0 (.)",
				"socksio @ 1.0.0 (.) [dependency-of] httpx @ 0.28.1 (.)",
				"typing-extensions @ 4.13.0 (.) [dependency-of] anyio @ 4.9.0 (.)",
			},
		},
		{
			name:    "uv - nested extras",
			fixture: "test-fixtures/uv/nested-extras",
			expectedRelationships: []string{
				"annotated-types @ 0.7.0 (.) [dependency-of] pydantic @ 2.11.0 (.)",
				"anyio @ 4.9.0 (.) [dependency-of] httpx @ 0.28.1 (.)",
				"anyio @ 4.9.0 (.) [dependency-of] starlette @ 0.37.2 (.)",
				"anyio @ 4.9.0 (.) [dependency-of] watchfiles @ 1.0.4 (.)",
				"certifi @ 2025.1.31 (.) [dependency-of] httpcore @ 1.0.7 (.)",
				"certifi @ 2025.1.31 (.) [dependency-of] httpx @ 0.28.1 (.)",
				"click @ 8.1.8 (.) [dependency-of] rich-toolkit @ 0.14.0 (.)",
				"click @ 8.1.8 (.) [dependency-of] typer @ 0.15.2 (.)",
				"click @ 8.1.8 (.) [dependency-of] uvicorn @ 0.34.0 (.)",
				"colorama @ 0.4.6 (.) [dependency-of] click @ 8.1.8 (.)",
				"colorama @ 0.4.6 (.) [dependency-of] uvicorn @ 0.34.0 (.)", // proof of uvicorn[standard]
				"dnspython @ 2.7.0 (.) [dependency-of] email-validator @ 2.2.0 (.)",
				"email-validator @ 2.2.0 (.) [dependency-of] fastapi @ 0.111.1 (.)",
				"fastapi @ 0.111.1 (.) [dependency-of] testpkg @ 0.1.0 (.)",
				"fastapi-cli @ 0.0.7 (.) [dependency-of] fastapi @ 0.111.1 (.)",
				"h11 @ 0.14.0 (.) [dependency-of] httpcore @ 1.0.7 (.)",
				"h11 @ 0.14.0 (.) [dependency-of] uvicorn @ 0.34.0 (.)",
				"httpcore @ 1.0.7 (.) [dependency-of] httpx @ 0.28.1 (.)",
				"httptools @ 0.6.4 (.) [dependency-of] uvicorn @ 0.34.0 (.)", // proof of uvicorn[standard]
				"httpx @ 0.28.1 (.) [dependency-of] fastapi @ 0.111.1 (.)",
				"idna @ 3.10 (.) [dependency-of] anyio @ 4.9.0 (.)",
				"idna @ 3.10 (.) [dependency-of] email-validator @ 2.2.0 (.)",
				"idna @ 3.10 (.) [dependency-of] httpx @ 0.28.1 (.)",
				"itsdangerous @ 2.2.0 (.) [dependency-of] fastapi @ 0.111.1 (.)",
				"jinja2 @ 3.1.6 (.) [dependency-of] fastapi @ 0.111.1 (.)",
				"markdown-it-py @ 3.0.0 (.) [dependency-of] rich @ 13.9.4 (.)",
				"markupsafe @ 3.0.2 (.) [dependency-of] jinja2 @ 3.1.6 (.)",
				"mdurl @ 0.1.2 (.) [dependency-of] markdown-it-py @ 3.0.0 (.)",
				"orjson @ 3.10.16 (.) [dependency-of] fastapi @ 0.111.1 (.)",
				"pydantic @ 2.11.0 (.) [dependency-of] fastapi @ 0.111.1 (.)",
				"pydantic @ 2.11.0 (.) [dependency-of] pydantic-extra-types @ 2.10.3 (.)",
				"pydantic @ 2.11.0 (.) [dependency-of] pydantic-settings @ 2.8.1 (.)",
				"pydantic-core @ 2.33.0 (.) [dependency-of] pydantic @ 2.11.0 (.)",
				"pydantic-extra-types @ 2.10.3 (.) [dependency-of] fastapi @ 0.111.1 (.)",
				"pydantic-settings @ 2.8.1 (.) [dependency-of] fastapi @ 0.111.1 (.)",
				"pygments @ 2.19.1 (.) [dependency-of] rich @ 13.9.4 (.)",
				"python-dotenv @ 1.1.0 (.) [dependency-of] pydantic-settings @ 2.8.1 (.)",
				"python-dotenv @ 1.1.0 (.) [dependency-of] uvicorn @ 0.34.0 (.)", // proof of uvicorn[standard]
				"python-multipart @ 0.0.20 (.) [dependency-of] fastapi @ 0.111.1 (.)",
				"pyyaml @ 6.0.2 (.) [dependency-of] fastapi @ 0.111.1 (.)",
				"pyyaml @ 6.0.2 (.) [dependency-of] uvicorn @ 0.34.0 (.)", // proof of uvicorn[standard]
				"rich @ 13.9.4 (.) [dependency-of] rich-toolkit @ 0.14.0 (.)",
				"rich @ 13.9.4 (.) [dependency-of] typer @ 0.15.2 (.)",
				"rich-toolkit @ 0.14.0 (.) [dependency-of] fastapi-cli @ 0.0.7 (.)",
				"shellingham @ 1.5.4 (.) [dependency-of] typer @ 0.15.2 (.)",
				"sniffio @ 1.3.1 (.) [dependency-of] anyio @ 4.9.0 (.)",
				"starlette @ 0.37.2 (.) [dependency-of] fastapi @ 0.111.1 (.)",
				"typer @ 0.15.2 (.) [dependency-of] fastapi-cli @ 0.0.7 (.)",
				"typing-extensions @ 4.13.0 (.) [dependency-of] anyio @ 4.9.0 (.)",
				"typing-extensions @ 4.13.0 (.) [dependency-of] fastapi @ 0.111.1 (.)",
				"typing-extensions @ 4.13.0 (.) [dependency-of] pydantic @ 2.11.0 (.)",
				"typing-extensions @ 4.13.0 (.) [dependency-of] pydantic-core @ 2.33.0 (.)",
				"typing-extensions @ 4.13.0 (.) [dependency-of] pydantic-extra-types @ 2.10.3 (.)",
				"typing-extensions @ 4.13.0 (.) [dependency-of] rich-toolkit @ 0.14.0 (.)",
				"typing-extensions @ 4.13.0 (.) [dependency-of] typer @ 0.15.2 (.)",
				"typing-extensions @ 4.13.0 (.) [dependency-of] typing-inspection @ 0.4.0 (.)",
				"typing-inspection @ 0.4.0 (.) [dependency-of] pydantic @ 2.11.0 (.)",
				"ujson @ 5.10.0 (.) [dependency-of] fastapi @ 0.111.1 (.)",
				"uvicorn @ 0.34.0 (.) [dependency-of] fastapi @ 0.111.1 (.)",
				"uvicorn @ 0.34.0 (.) [dependency-of] fastapi-cli @ 0.0.7 (.)",
				"uvloop @ 0.21.0 (.) [dependency-of] uvicorn @ 0.34.0 (.)",     // proof of uvicorn[standard]
				"watchfiles @ 1.0.4 (.) [dependency-of] uvicorn @ 0.34.0 (.)",  // proof of uvicorn[standard]
				"websockets @ 15.0.1 (.) [dependency-of] uvicorn @ 0.34.0 (.)", // proof of uvicorn[standard]
			},
		},
		{
			name:    "uv - conflicting extras",
			fixture: "test-fixtures/uv/conflicting-with-extras",
			expectedRelationships: []string{
				"anyio @ 4.6.2.post1 (.) [dependency-of] httpx @ 0.28.1 (.)",
				"brotli @ 1.1.0 (.) [dependency-of] httpx @ 0.28.1 (.)",
				"brotlicffi @ 1.1.0.0 (.) [dependency-of] httpx @ 0.28.1 (.)",
				"certifi @ 2025.1.31 (.) [dependency-of] httpcore @ 1.0.7 (.)",
				"certifi @ 2025.1.31 (.) [dependency-of] httpx @ 0.28.1 (.)",
				"cffi @ 1.17.1 (.) [dependency-of] brotlicffi @ 1.1.0.0 (.)",
				"colorama @ 0.4.6 (.) [dependency-of] rich @ 0.3.3 (.)",
				"h11 @ 0.14.0 (.) [dependency-of] httpcore @ 1.0.7 (.)",
				"h2 @ 4.2.0 (.) [dependency-of] httpx @ 0.28.1 (.)",
				"hpack @ 4.1.0 (.) [dependency-of] h2 @ 4.2.0 (.)",
				"httpcore @ 1.0.7 (.) [dependency-of] httpx @ 0.28.1 (.)",
				"httpx @ 0.28.1 (.) [dependency-of] testpkg @ 0.1.0 (.)",
				"hyperframe @ 6.1.0 (.) [dependency-of] h2 @ 4.2.0 (.)",
				"idna @ 3.10 (.) [dependency-of] anyio @ 4.6.2.post1 (.)",
				"idna @ 3.10 (.) [dependency-of] httpx @ 0.28.1 (.)",
				"pprintpp @ 0.4.0 (.) [dependency-of] rich @ 0.3.3 (.)",
				"pycparser @ 2.22 (.) [dependency-of] cffi @ 1.17.1 (.)",
				"sniffio @ 1.3.1 (.) [dependency-of] anyio @ 4.6.2.post1 (.)",
				"socksio @ 1.0.0 (.) [dependency-of] httpx @ 0.28.1 (.)",
				"typing-extensions @ 3.10.0.2 (.) [dependency-of] rich @ 0.3.3 (.)",
				// ideally we should NOT see these dependencies. However, they are technically installed in the environment
				// and an import is present in httpx for each of these, so in theory they are actually dependencies even
				// though our pyproject.toml looks like this:
				//
				//     [tool.poetry.dependencies]
				//     python = "^3.11"
				//     httpx = {extras = ["brotli", "http2", "socks"], version = "^0.27.0"}
				//     pygments = "1.6"
				//     click = "<8"
				//     rich = "<10"
				//
				// note that pygments, click, and rich are installed outside of the allowable ranges for the given
				// httpx package version constraints, per the poetry.lock:
				//
				//     # for package httpx
				//     [package.extras]
				//     cli = ["click (==8.*)", "pygments (==2.*)", "rich (>=10,<14)"]
				//
				// note: the pyproject.toml and uv.lock state are consistent with each other (just with
				// "uv sync" and nothing was forced!)
				"click @ 7.1.2 (.) [dependency-of] testpkg @ 0.1.0 (.)",
				"pygments @ 1.6 (.) [dependency-of] testpkg @ 0.1.0 (.)",
				"rich @ 0.3.3 (.) [dependency-of] testpkg @ 0.1.0 (.)",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				WithPackageStringer(stringPackage).
				ExpectsRelationshipStrings(test.expectedRelationships).
				TestCataloger(t, NewPackageCataloger(DefaultCatalogerConfig()))
		})
	}
}

func Test_PackageCataloger_SitePackageRelationships(t *testing.T) {
	tests := []struct {
		name                  string
		fixture               string
		expectedRelationships []string
	}{
		{
			name:    "with multiple python installations and virtual envs",
			fixture: "image-multi-site-package",
			expectedRelationships: []string{
				// purely python 3.9 dist-packages
				//
				// in the container, you can get a sense for dependencies with :
				//   $ python3.9 -m pip list | tail -n +3 | awk '{print $1}' | xargs python3.9 -m pip show | grep -e 'Name:' -e 'Requires:' -e '\-\-\-'
				//
				// which approximates to (all in system packages):
				//
				// - beautifulsoup4: soupsieve
				// - requests: certifi, chardet, idna, urllib3
				// - blessed: six, wcwidth
				// - virtualenv: distlib, filelock, platformdirs
				"certifi @ 2020.12.5 (/usr/local/lib/python3.9/dist-packages) [dependency-of] requests @ 2.25.0 (/usr/local/lib/python3.9/dist-packages)",
				"certifi @ 2020.12.5 (/usr/local/lib/python3.9/dist-packages) [dependency-of] urllib3 @ 1.26.18 (/usr/local/lib/python3.9/dist-packages)", // available when extra == "secure", but another dependency is primarily installing it
				"chardet @ 3.0.4 (/usr/local/lib/python3.9/dist-packages) [dependency-of] requests @ 2.25.0 (/usr/local/lib/python3.9/dist-packages)",
				"distlib @ 0.3.9 (/usr/local/lib/python3.9/dist-packages) [dependency-of] virtualenv @ 20.31.2 (/usr/local/lib/python3.9/dist-packages)",
				"filelock @ 3.18.0 (/usr/local/lib/python3.9/dist-packages) [dependency-of] virtualenv @ 20.31.2 (/usr/local/lib/python3.9/dist-packages)",
				"idna @ 2.10 (/usr/local/lib/python3.9/dist-packages) [dependency-of] requests @ 2.25.0 (/usr/local/lib/python3.9/dist-packages)",
				"idna @ 2.10 (/usr/local/lib/python3.9/dist-packages) [dependency-of] urllib3 @ 1.26.18 (/usr/local/lib/python3.9/dist-packages)", // available when extra == "secure", but another dependency is primarily installing it
				"platformdirs @ 4.3.8 (/usr/local/lib/python3.9/dist-packages) [dependency-of] virtualenv @ 20.31.2 (/usr/local/lib/python3.9/dist-packages)",
				"six @ 1.16.0 (/usr/local/lib/python3.9/dist-packages) [dependency-of] blessed @ 1.20.0 (/usr/local/lib/python3.9/dist-packages)",
				"soupsieve @ 2.2.1 (/usr/local/lib/python3.9/dist-packages) [dependency-of] beautifulsoup4 @ 4.9.3 (/usr/local/lib/python3.9/dist-packages)",
				"urllib3 @ 1.26.18 (/usr/local/lib/python3.9/dist-packages) [dependency-of] requests @ 2.25.0 (/usr/local/lib/python3.9/dist-packages)",
				"virtualenv @ 20.31.2 (/usr/local/lib/python3.9/dist-packages) [dependency-of] filelock @ 3.18.0 (/usr/local/lib/python3.9/dist-packages)", // available when extra == "testing", but we are installing it
				"wcwidth @ 0.2.13 (/usr/local/lib/python3.9/dist-packages) [dependency-of] blessed @ 1.20.0 (/usr/local/lib/python3.9/dist-packages)",

				// purely python 3.8 dist-packages
				//
				// in the container, you can get a sense for dependencies with :
				//   $ python3.8 -m pip list | tail -n +3 | awk '{print $1}' | xargs python3.8 -m pip show | grep -e 'Name:' -e 'Requires:' -e '\-\-\-'
				//
				// which approximates to (all in system packages):
				//
				// - beautifulsoup4: soupsieve
				// - requests: certifi, chardet, idna, urllib3
				// - runs: xmod
				// - virtualenv: distlib, filelock, platformdirs
				"certifi @ 2020.12.5 (/usr/local/lib/python3.8/dist-packages) [dependency-of] requests @ 2.25.0 (/usr/local/lib/python3.8/dist-packages)",
				"certifi @ 2020.12.5 (/usr/local/lib/python3.8/dist-packages) [dependency-of] urllib3 @ 1.26.18 (/usr/local/lib/python3.8/dist-packages)", // available when extra == "secure", but another dependency is primarily installing it
				"chardet @ 3.0.4 (/usr/local/lib/python3.8/dist-packages) [dependency-of] requests @ 2.25.0 (/usr/local/lib/python3.8/dist-packages)",
				"distlib @ 0.3.9 (/usr/local/lib/python3.8/dist-packages) [dependency-of] virtualenv @ 20.31.2 (/usr/local/lib/python3.8/dist-packages)",
				"filelock @ 3.16.1 (/usr/local/lib/python3.8/dist-packages) [dependency-of] virtualenv @ 20.31.2 (/usr/local/lib/python3.8/dist-packages)",
				"idna @ 2.10 (/usr/local/lib/python3.8/dist-packages) [dependency-of] requests @ 2.25.0 (/usr/local/lib/python3.8/dist-packages)",
				"idna @ 2.10 (/usr/local/lib/python3.8/dist-packages) [dependency-of] urllib3 @ 1.26.18 (/usr/local/lib/python3.8/dist-packages)", // available when extra == "secure", but another dependency is primarily installing it
				"platformdirs @ 4.3.6 (/usr/local/lib/python3.8/dist-packages) [dependency-of] virtualenv @ 20.31.2 (/usr/local/lib/python3.8/dist-packages)",
				"soupsieve @ 2.2 (/usr/local/lib/python3.8/dist-packages) [dependency-of] beautifulsoup4 @ 4.9.2 (/usr/local/lib/python3.8/dist-packages)",
				"urllib3 @ 1.26.18 (/usr/local/lib/python3.8/dist-packages) [dependency-of] requests @ 2.25.0 (/usr/local/lib/python3.8/dist-packages)",
				"virtualenv @ 20.31.2 (/usr/local/lib/python3.8/dist-packages) [dependency-of] filelock @ 3.16.1 (/usr/local/lib/python3.8/dist-packages)", // available when extra == "testing", but we are installing it
				"xmod @ 1.8.1 (/usr/local/lib/python3.8/dist-packages) [dependency-of] runs @ 1.2.2 (/usr/local/lib/python3.8/dist-packages)",

				// project 1 virtual env
				//
				// in the container, you can get a sense for dependencies with :
				//   $ source /app/project1/venv/bin/activate
				//   $ pip list | tail -n +3 | awk '{print $1}' | xargs pip show | grep -e 'Name:' -e 'Requires:' -e '\-\-\-' -e 'Location:' | grep -A 1 -B 1 '\-packages'
				//
				// which approximates to (some in virtual env, some in system packages):
				//
				// - beautifulsoup4: soupsieve
				// - requests [SYSTEM]: certifi [SYSTEM], chardet [SYSTEM], idna [SYSTEM], urllib3 [SYSTEM]
				// - blessed [SYSTEM]: six [SYSTEM], wcwidth [SYSTEM]
				// - virtualenv [SYSTEM]: distlib [SYSTEM], filelock [SYSTEM], platformdirs [SYSTEM]
				// - inquirer: python-editor [SYSTEM], blessed [SYSTEM], readchar
				//
				// Note: we'll only see new relationships, so any relationship where there is at least one new player (in FROM or TO)
				"blessed @ 1.20.0 (/usr/local/lib/python3.9/dist-packages) [dependency-of] inquirer @ 3.0.0 (/app/project1/venv/lib/python3.9/site-packages)",      // note: depends on global site package!
				"python-editor @ 1.0.4 (/usr/local/lib/python3.9/dist-packages) [dependency-of] inquirer @ 3.0.0 (/app/project1/venv/lib/python3.9/site-packages)", // note: depends on global site package!
				"readchar @ 4.2.1 (/app/project1/venv/lib/python3.9/site-packages) [dependency-of] inquirer @ 3.0.0 (/app/project1/venv/lib/python3.9/site-packages)",
				"setuptools @ 44.0.0 (/app/project1/venv/lib/python3.9/site-packages) [dependency-of] virtualenv @ 20.31.2 (/usr/local/lib/python3.9/dist-packages)", // available when extra == "test", but we are installing it
				"soupsieve @ 2.3 (/app/project1/venv/lib/python3.9/site-packages) [dependency-of] beautifulsoup4 @ 4.10.0 (/app/project1/venv/lib/python3.9/site-packages)",

				// project 2 virtual env
				//
				// in the container, you can get a sense for dependencies with :
				//   $ source /app/project2/venv/bin/activate
				//   $ pip list | tail -n +3 | awk '{print $1}' | xargs pip show | grep -e 'Name:' -e 'Requires:' -e '\-\-\-' -e 'Location:'
				//
				// which approximates to (all in virtual env):
				//
				// - blessed: six, wcwidth
				// - editor: runs, xmod
				// - runs: xmod
				// - inquirer: editor, blessed, readchar
				"blessed @ 1.20.0 (/app/project2/venv/lib/python3.8/site-packages) [dependency-of] inquirer @ 3.2.4 (/app/project2/venv/lib/python3.8/site-packages)",
				"editor @ 1.6.6 (/app/project2/venv/lib/python3.8/site-packages) [dependency-of] inquirer @ 3.2.4 (/app/project2/venv/lib/python3.8/site-packages)",
				"readchar @ 4.1.0 (/app/project2/venv/lib/python3.8/site-packages) [dependency-of] inquirer @ 3.2.4 (/app/project2/venv/lib/python3.8/site-packages)",
				"runs @ 1.2.2 (/app/project2/venv/lib/python3.8/site-packages) [dependency-of] editor @ 1.6.6 (/app/project2/venv/lib/python3.8/site-packages)",
				"six @ 1.16.0 (/app/project2/venv/lib/python3.8/site-packages) [dependency-of] blessed @ 1.20.0 (/app/project2/venv/lib/python3.8/site-packages)",
				"wcwidth @ 0.2.13 (/app/project2/venv/lib/python3.8/site-packages) [dependency-of] blessed @ 1.20.0 (/app/project2/venv/lib/python3.8/site-packages)",
				"xmod @ 1.8.1 (/app/project2/venv/lib/python3.8/site-packages) [dependency-of] editor @ 1.6.6 (/app/project2/venv/lib/python3.8/site-packages)",
				"xmod @ 1.8.1 (/app/project2/venv/lib/python3.8/site-packages) [dependency-of] runs @ 1.2.2 (/app/project2/venv/lib/python3.8/site-packages)",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				WithImageResolver(t, test.fixture).
				WithPackageStringer(stringPackage).
				ExpectsRelationshipStrings(test.expectedRelationships).
				TestCataloger(t, NewInstalledPackageCataloger())
		})
	}
}

func stringPackage(p pkg.Package) string {
	locs := p.Locations.ToSlice()
	var loc string
	if len(locs) > 0 {
		// we want the location of the site-packages, not the metadata file
		loc = path.Dir(path.Dir(p.Locations.ToSlice()[0].RealPath))
	}

	return fmt.Sprintf("%s @ %s (%s)", p.Name, p.Version, loc)
}

func mustContentsFromLocation(t *testing.T, contentsPath string, offset ...int) string {
	t.Helper() // Marks this function as a test helper for cleaner error reporting
	contents, err := os.ReadFile(contentsPath)
	if err != nil {
		t.Fatalf("failed to read file %s: %v", contentsPath, err)
	}

	if len(offset) == 0 {
		return string(contents)
	}

	if len(offset) != 2 {
		t.Fatalf("invalid offset provided, expected two integers: start and end")
	}
	start, end := offset[0], offset[1]

	if start < 0 || end > len(contents) || start > end {
		t.Fatalf("invalid offset range: start=%d, end=%d, content length=%d", start, end, len(contents))
	}

	return string(contents[start:end])
}
