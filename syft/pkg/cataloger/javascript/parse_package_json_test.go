package javascript

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
)

func TestParsePackageJSON(t *testing.T) {
	tests := []struct {
		Fixture     string
		ExpectedPkg pkg.Package
	}{
		{
			Fixture: "test-fixtures/pkg-json/package.json",
			ExpectedPkg: pkg.Package{
				Name:         "npm",
				Version:      "6.14.6",
				PURL:         "pkg:npm/npm@6.14.6",
				Type:         pkg.NpmPkg,
				Licenses:     internal.LogicalStrings{Simple: []string{"Artistic-2.0"}},
				Language:     pkg.JavaScript,
				MetadataType: pkg.NpmPackageJSONMetadataType,
				Metadata: pkg.NpmPackageJSONMetadata{
					Name:     "npm",
					Version:  "6.14.6",
					Author:   "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)",
					Homepage: "https://docs.npmjs.com/",
					URL:      "https://github.com/npm/cli",
					Licenses: []string{"Artistic-2.0"},
				},
			},
		},
		{
			Fixture: "test-fixtures/pkg-json/package-license-object.json",
			ExpectedPkg: pkg.Package{
				Name:         "npm",
				Version:      "6.14.6",
				PURL:         "pkg:npm/npm@6.14.6",
				Type:         pkg.NpmPkg,
				Licenses:     internal.LogicalStrings{Simple: []string{"ISC"}},
				Language:     pkg.JavaScript,
				MetadataType: pkg.NpmPackageJSONMetadataType,
				Metadata: pkg.NpmPackageJSONMetadata{
					Name:     "npm",
					Version:  "6.14.6",
					Author:   "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)",
					Homepage: "https://docs.npmjs.com/",
					URL:      "https://github.com/npm/cli",
					Licenses: []string{"ISC"},
				},
			},
		},
		{
			Fixture: "test-fixtures/pkg-json/package-license-objects.json",
			ExpectedPkg: pkg.Package{
				Name:         "npm",
				Version:      "6.14.6",
				PURL:         "pkg:npm/npm@6.14.6",
				Type:         pkg.NpmPkg,
				Licenses:     internal.LogicalStrings{Simple: []string{"MIT", "Apache-2.0"}},
				Language:     pkg.JavaScript,
				MetadataType: pkg.NpmPackageJSONMetadataType,
				Metadata: pkg.NpmPackageJSONMetadata{
					Name:     "npm",
					Version:  "6.14.6",
					Author:   "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)",
					Homepage: "https://docs.npmjs.com/",
					URL:      "https://github.com/npm/cli",
					Licenses: []string{"MIT", "Apache-2.0"},
				},
			},
		},
		{
			Fixture: "test-fixtures/pkg-json/package-malformed-license.json",
			ExpectedPkg: pkg.Package{
				Name:         "npm",
				Version:      "6.14.6",
				PURL:         "pkg:npm/npm@6.14.6",
				Type:         pkg.NpmPkg,
				Language:     pkg.JavaScript,
				MetadataType: pkg.NpmPackageJSONMetadataType,
				Metadata: pkg.NpmPackageJSONMetadata{
					Name:     "npm",
					Version:  "6.14.6",
					Author:   "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)",
					Homepage: "https://docs.npmjs.com/",
					URL:      "https://github.com/npm/cli",
					Licenses: nil,
				},
			},
		},
		{
			Fixture: "test-fixtures/pkg-json/package-no-license.json",
			ExpectedPkg: pkg.Package{
				Name:         "npm",
				Version:      "6.14.6",
				PURL:         "pkg:npm/npm@6.14.6",
				Type:         pkg.NpmPkg,
				Language:     pkg.JavaScript,
				MetadataType: pkg.NpmPackageJSONMetadataType,
				Metadata: pkg.NpmPackageJSONMetadata{
					Name:     "npm",
					Version:  "6.14.6",
					Author:   "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)",
					Homepage: "https://docs.npmjs.com/",
					URL:      "https://github.com/npm/cli",
					Licenses: []string{},
				},
			},
		},
		{
			Fixture: "test-fixtures/pkg-json/package-nested-author.json",
			ExpectedPkg: pkg.Package{
				Name:         "npm",
				Version:      "6.14.6",
				PURL:         "pkg:npm/npm@6.14.6",
				Type:         pkg.NpmPkg,
				Licenses:     internal.LogicalStrings{Simple: []string{"Artistic-2.0"}},
				Language:     pkg.JavaScript,
				MetadataType: pkg.NpmPackageJSONMetadataType,
				Metadata: pkg.NpmPackageJSONMetadata{
					Name:     "npm",
					Version:  "6.14.6",
					Author:   "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)",
					Homepage: "https://docs.npmjs.com/",
					URL:      "https://github.com/npm/cli",
					Licenses: []string{"Artistic-2.0"},
				},
			},
		},
		{
			Fixture: "test-fixtures/pkg-json/package-repo-string.json",
			ExpectedPkg: pkg.Package{
				Name:         "function-bind",
				Version:      "1.1.1",
				PURL:         "pkg:npm/function-bind@1.1.1",
				Type:         pkg.NpmPkg,
				Licenses:     internal.LogicalStrings{Simple: []string{"MIT"}},
				Language:     pkg.JavaScript,
				MetadataType: pkg.NpmPackageJSONMetadataType,
				Metadata: pkg.NpmPackageJSONMetadata{
					Name:     "function-bind",
					Version:  "1.1.1",
					Author:   "Raynos <raynos2@gmail.com>",
					Homepage: "https://github.com/Raynos/function-bind",
					URL:      "git://github.com/Raynos/function-bind.git",
					Licenses: []string{"MIT"},
				},
			},
		},
		{
			Fixture: "test-fixtures/pkg-json/package-private.json",
			ExpectedPkg: pkg.Package{
				Name:         "npm",
				Version:      "6.14.6",
				PURL:         "pkg:npm/npm@6.14.6",
				Type:         pkg.NpmPkg,
				Licenses:     internal.LogicalStrings{Simple: []string{"Artistic-2.0"}},
				Language:     pkg.JavaScript,
				MetadataType: pkg.NpmPackageJSONMetadataType,
				Metadata: pkg.NpmPackageJSONMetadata{
					Name:     "npm",
					Version:  "6.14.6",
					Author:   "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)",
					Homepage: "https://docs.npmjs.com/",
					URL:      "https://github.com/npm/cli",
					Licenses: []string{"Artistic-2.0"},
					Private:  true,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Fixture, func(t *testing.T) {
			test.ExpectedPkg.Locations.Add(source.NewLocation(test.Fixture))
			pkgtest.TestFileParser(t, test.Fixture, parsePackageJSON, []pkg.Package{test.ExpectedPkg}, nil)
		})
	}
}

func TestParsePackageJSON_Partial(t *testing.T) { // see https://github.com/anchore/syft/issues/311
	const fixtureFile = "test-fixtures/pkg-json/package-partial.json"

	pkgtest.TestFileParser(t, fixtureFile, parsePackageJSON, nil, nil)
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
