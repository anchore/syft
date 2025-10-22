package javascript

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParsePackageJSON(t *testing.T) {
	ctx := context.TODO()
	tests := []struct {
		Fixture     string
		ExpectedPkg pkg.Package
	}{
		{
			Fixture: "test-fixtures/pkg-json/package.json",
			ExpectedPkg: pkg.Package{
				Name:     "npm",
				Version:  "6.14.6",
				PURL:     "pkg:npm/npm@6.14.6",
				Type:     pkg.NpmPkg,
				Language: pkg.JavaScript,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocationsWithContext(ctx, "Artistic-2.0", file.NewLocation("test-fixtures/pkg-json/package.json")),
				),
				Metadata: pkg.NpmPackage{
					Name:        "npm",
					Version:     "6.14.6",
					Author:      "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)",
					Homepage:    "https://docs.npmjs.com/",
					URL:         "https://github.com/npm/cli",
					Description: "a package manager for JavaScript",
				},
			},
		},
		{
			Fixture: "test-fixtures/pkg-json/package-license-object.json",
			ExpectedPkg: pkg.Package{
				Name:     "npm",
				Version:  "6.14.6",
				PURL:     "pkg:npm/npm@6.14.6",
				Type:     pkg.NpmPkg,
				Language: pkg.JavaScript,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocationsWithContext(ctx, "ISC", file.NewLocation("test-fixtures/pkg-json/package-license-object.json")),
				),
				Metadata: pkg.NpmPackage{
					Name:        "npm",
					Version:     "6.14.6",
					Author:      "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)",
					Homepage:    "https://docs.npmjs.com/",
					URL:         "https://github.com/npm/cli",
					Description: "a package manager for JavaScript",
				},
			},
		},
		{
			Fixture: "test-fixtures/pkg-json/package-license-objects.json",
			ExpectedPkg: pkg.Package{
				Name:    "npm",
				Version: "6.14.6",
				PURL:    "pkg:npm/npm@6.14.6",
				Type:    pkg.NpmPkg,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocationsWithContext(ctx, "MIT", file.NewLocation("test-fixtures/pkg-json/package-license-objects.json")),
					pkg.NewLicenseFromLocationsWithContext(ctx, "Apache-2.0", file.NewLocation("test-fixtures/pkg-json/package-license-objects.json")),
				),
				Language: pkg.JavaScript,
				Metadata: pkg.NpmPackage{
					Name:        "npm",
					Version:     "6.14.6",
					Author:      "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)",
					Homepage:    "https://docs.npmjs.com/",
					URL:         "https://github.com/npm/cli",
					Description: "a package manager for JavaScript",
				},
			},
		},
		{
			Fixture: "test-fixtures/pkg-json/package-malformed-license.json",
			ExpectedPkg: pkg.Package{
				Name:     "npm",
				Version:  "6.14.6",
				PURL:     "pkg:npm/npm@6.14.6",
				Type:     pkg.NpmPkg,
				Language: pkg.JavaScript,
				Metadata: pkg.NpmPackage{
					Name:        "npm",
					Version:     "6.14.6",
					Author:      "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)",
					Homepage:    "https://docs.npmjs.com/",
					URL:         "https://github.com/npm/cli",
					Description: "a package manager for JavaScript",
				},
			},
		},
		{
			Fixture: "test-fixtures/pkg-json/package-no-license.json",
			ExpectedPkg: pkg.Package{
				Name:     "npm",
				Version:  "6.14.6",
				PURL:     "pkg:npm/npm@6.14.6",
				Type:     pkg.NpmPkg,
				Language: pkg.JavaScript,
				Metadata: pkg.NpmPackage{
					Name:        "npm",
					Version:     "6.14.6",
					Author:      "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)",
					Homepage:    "https://docs.npmjs.com/",
					URL:         "https://github.com/npm/cli",
					Description: "a package manager for JavaScript",
				},
			},
		},
		{
			Fixture: "test-fixtures/pkg-json/package-nested-author.json",
			ExpectedPkg: pkg.Package{
				Name:    "npm",
				Version: "6.14.6",
				PURL:    "pkg:npm/npm@6.14.6",
				Type:    pkg.NpmPkg,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocationsWithContext(ctx, "Artistic-2.0", file.NewLocation("test-fixtures/pkg-json/package-nested-author.json")),
				),
				Language: pkg.JavaScript,
				Metadata: pkg.NpmPackage{
					Name:        "npm",
					Version:     "6.14.6",
					Author:      "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)",
					Homepage:    "https://docs.npmjs.com/",
					URL:         "https://github.com/npm/cli",
					Description: "a package manager for JavaScript",
				},
			},
		},
		{
			Fixture: "test-fixtures/pkg-json/package-repo-string.json",
			ExpectedPkg: pkg.Package{
				Name:    "function-bind",
				Version: "1.1.1",
				PURL:    "pkg:npm/function-bind@1.1.1",
				Type:    pkg.NpmPkg,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocationsWithContext(ctx, "MIT", file.NewLocation("test-fixtures/pkg-json/package-repo-string.json")),
				),
				Language: pkg.JavaScript,
				Metadata: pkg.NpmPackage{
					Name:        "function-bind",
					Version:     "1.1.1",
					Author:      "Raynos <raynos2@gmail.com>, Raynos, Jordan Harband (https://github.com/ljharb)",
					Homepage:    "https://github.com/Raynos/function-bind",
					URL:         "git://github.com/Raynos/function-bind.git",
					Description: "Implementation of Function.prototype.bind",
				},
			},
		},
		{
			Fixture: "test-fixtures/pkg-json/package-private.json",
			ExpectedPkg: pkg.Package{
				Name:    "npm",
				Version: "6.14.6",
				PURL:    "pkg:npm/npm@6.14.6",
				Type:    pkg.NpmPkg,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocationsWithContext(ctx, "Artistic-2.0", file.NewLocation("test-fixtures/pkg-json/package-private.json")),
				),
				Language: pkg.JavaScript,
				Metadata: pkg.NpmPackage{
					Name:        "npm",
					Version:     "6.14.6",
					Author:      "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)",
					Homepage:    "https://docs.npmjs.com/",
					URL:         "https://github.com/npm/cli",
					Private:     true,
					Description: "a package manager for JavaScript",
				},
			},
		},
		{
			Fixture: "test-fixtures/pkg-json/package-author-non-standard.json",
			ExpectedPkg: pkg.Package{
				Name:    "npm",
				Version: "6.14.6",
				PURL:    "pkg:npm/npm@6.14.6",
				Type:    pkg.NpmPkg,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocationsWithContext(ctx, "Artistic-2.0", file.NewLocation("test-fixtures/pkg-json/package-author-non-standard.json")),
				),
				Language: pkg.JavaScript,
				Metadata: pkg.NpmPackage{
					Name:        "npm",
					Version:     "6.14.6",
					Author:      "npm Inc. (https://www.npmjs.com/)",
					Homepage:    "https://docs.npmjs.com/",
					URL:         "https://github.com/npm/cli",
					Description: "a package manager for JavaScript",
				},
			},
		},
		{
			Fixture: "test-fixtures/pkg-json/package-authors-array.json",
			ExpectedPkg: pkg.Package{
				Name:    "npm",
				Version: "6.14.6",
				PURL:    "pkg:npm/npm@6.14.6",
				Type:    pkg.NpmPkg,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocationsWithContext(ctx, "Artistic-2.0", file.NewLocation("test-fixtures/pkg-json/package-authors-array.json")),
				),
				Language: pkg.JavaScript,
				Metadata: pkg.NpmPackage{
					Name:        "npm",
					Version:     "6.14.6",
					Author:      "Harry Potter <hp@hogwards.com> (http://youknowwho.com/), John Smith <j.smith@something.com> (http://awebsite.com/)",
					Homepage:    "https://docs.npmjs.com/",
					URL:         "https://github.com/npm/cli",
					Description: "a package manager for JavaScript",
				},
			},
		},
		{
			Fixture: "test-fixtures/pkg-json/package-authors-objects.json",
			ExpectedPkg: pkg.Package{
				Name:    "npm",
				Version: "6.14.6",
				PURL:    "pkg:npm/npm@6.14.6",
				Type:    pkg.NpmPkg,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocationsWithContext(ctx, "Artistic-2.0", file.NewLocation("test-fixtures/pkg-json/package-authors-objects.json")),
				),
				Language: pkg.JavaScript,
				Metadata: pkg.NpmPackage{
					Name:        "npm",
					Version:     "6.14.6",
					Author:      "Harry Potter <hp@hogwards.com> (http://youknowwho.com/), John Smith <j.smith@something.com> (http://awebsite.com/)",
					Homepage:    "https://docs.npmjs.com/",
					URL:         "https://github.com/npm/cli",
					Description: "a package manager for JavaScript",
				},
			},
		},
		{
			Fixture: "test-fixtures/pkg-json/package-both-author-and-authors.json",
			ExpectedPkg: pkg.Package{
				Name:    "npm",
				Version: "6.14.6",
				PURL:    "pkg:npm/npm@6.14.6",
				Type:    pkg.NpmPkg,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocationsWithContext(ctx, "Artistic-2.0", file.NewLocation("test-fixtures/pkg-json/package-both-author-and-authors.json")),
				),
				Language: pkg.JavaScript,
				Metadata: pkg.NpmPackage{
					Name:        "npm",
					Version:     "6.14.6",
					Author:      "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me), Harry Potter <hp@hogwards.com> (http://youknowwho.com/), John Smith <j.smith@something.com> (http://awebsite.com/)",
					Homepage:    "https://docs.npmjs.com/",
					URL:         "https://github.com/npm/cli",
					Description: "a package manager for JavaScript",
				},
			},
		},
		{
			Fixture: "test-fixtures/pkg-json/package-contributors.json",
			ExpectedPkg: pkg.Package{
				Name:    "npm",
				Version: "6.14.6",
				PURL:    "pkg:npm/npm@6.14.6",
				Type:    pkg.NpmPkg,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocationsWithContext(ctx, "Artistic-2.0", file.NewLocation("test-fixtures/pkg-json/package-contributors.json")),
				),
				Language: pkg.JavaScript,
				Metadata: pkg.NpmPackage{
					Name:        "npm",
					Version:     "6.14.6",
					Author:      "Alice Contributor <alice@example.com>, Bob Helper <bob@example.com>",
					Homepage:    "https://docs.npmjs.com/",
					URL:         "https://github.com/npm/cli",
					Description: "a package manager for JavaScript",
				},
			},
		},
		{
			Fixture: "test-fixtures/pkg-json/package-maintainers.json",
			ExpectedPkg: pkg.Package{
				Name:    "npm",
				Version: "6.14.6",
				PURL:    "pkg:npm/npm@6.14.6",
				Type:    pkg.NpmPkg,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocationsWithContext(ctx, "Artistic-2.0", file.NewLocation("test-fixtures/pkg-json/package-maintainers.json")),
				),
				Language: pkg.JavaScript,
				Metadata: pkg.NpmPackage{
					Name:        "npm",
					Version:     "6.14.6",
					Author:      "Charlie Maintainer <charlie@example.com>, Diana Keeper <diana@example.com>",
					Homepage:    "https://docs.npmjs.com/",
					URL:         "https://github.com/npm/cli",
					Description: "a package manager for JavaScript",
				},
			},
		},
		{
			Fixture: "test-fixtures/pkg-json/package-all-author-fields.json",
			ExpectedPkg: pkg.Package{
				Name:    "npm",
				Version: "6.14.6",
				PURL:    "pkg:npm/npm@6.14.6",
				Type:    pkg.NpmPkg,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocationsWithContext(ctx, "Artistic-2.0", file.NewLocation("test-fixtures/pkg-json/package-all-author-fields.json")),
				),
				Language: pkg.JavaScript,
				Metadata: pkg.NpmPackage{
					Name:        "npm",
					Version:     "6.14.6",
					Author:      "Main Author <main@example.com>, Second Author <second@example.com>, Contrib One <contrib1@example.com>, Maintainer One <maintain1@example.com>",
					Homepage:    "https://docs.npmjs.com/",
					URL:         "https://github.com/npm/cli",
					Description: "a package manager for JavaScript",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Fixture, func(t *testing.T) {
			test.ExpectedPkg.Locations.Add(file.NewLocation(test.Fixture))
			pkgtest.TestFileParser(t, test.Fixture, parsePackageJSON, []pkg.Package{test.ExpectedPkg}, nil)
		})
	}
}

func Test_corruptPackageJSON(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/corrupt/package.json").
		WithError().
		TestParser(t, parsePackageJSON)
}

func TestParsePackageJSON_Partial(t *testing.T) { // see https://github.com/anchore/syft/issues/311
	const fixtureFile = "test-fixtures/pkg-json/package-partial.json"

	// raise package.json files as packages with any information we find, these will be filtered out
	// according to compliance rules later
	expectedPkgs := []pkg.Package{
		{
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			PURL:      packageURL("", ""),
			Metadata:  pkg.NpmPackage{},
			Locations: file.NewLocationSet(file.NewLocation(fixtureFile)),
		},
	}
	pkgtest.TestFileParser(t, fixtureFile, parsePackageJSON, expectedPkgs, nil)
}

func Test_pathContainsNodeModulesDirectory(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		// positive
		{
			path:     "something/node_modules/package",
			expected: true,
		},
		{
			path:     "node_modules/package",
			expected: true,
		},
		{
			path:     "something/node_modules",
			expected: true,
		},
		{
			path:     "\\something\\node_modules\\",
			expected: true,
		},
		{
			path:     "\\something\\node_modules",
			expected: true,
		},
		// negative
		{
			path:     "something/node_bogus_modules",
			expected: false,
		},
		{
			path:     "something/node_modules_bogus",
			expected: false,
		},
		{
			path:     "something/node_bogus_modules/package",
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			assert.Equal(t, test.expected, pathContainsNodeModulesDirectory(test.path))
		})
	}
}
