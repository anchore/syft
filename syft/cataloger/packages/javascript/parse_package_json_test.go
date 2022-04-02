package javascript

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
	"github.com/stretchr/testify/assert"
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
				Type:         pkg.NpmPkg,
				Licenses:     []string{"Artistic-2.0"},
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
				Type:         pkg.NpmPkg,
				Licenses:     []string{"ISC"},
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
				Type:         pkg.NpmPkg,
				Licenses:     []string{"MIT", "Apache-2.0"},
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
			Fixture: "test-fixtures/pkg-json/package-no-license.json",
			ExpectedPkg: pkg.Package{
				Name:         "npm",
				Version:      "6.14.6",
				Type:         pkg.NpmPkg,
				Licenses:     []string{},
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
				Type:         pkg.NpmPkg,
				Licenses:     []string{"Artistic-2.0"},
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
				Type:         pkg.NpmPkg,
				Licenses:     []string{"MIT"},
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
	}

	for _, test := range tests {
		t.Run(test.Fixture, func(t *testing.T) {
			fixture, err := os.Open(test.Fixture)
			if err != nil {
				t.Fatalf("failed to open fixture: %+v", err)
			}

			actual, _, err := parsePackageJSON("", fixture)
			if err != nil {
				t.Fatalf("failed to parse package-lock.json: %+v", err)
			}
			if len(actual) != 1 {
				for _, a := range actual {
					t.Log("   ", a)
				}
				t.Fatalf("unexpected package count: %d!=1", len(actual))
			}

			for _, d := range deep.Equal(actual[0], &test.ExpectedPkg) {

				t.Errorf("diff: %+v", d)
			}
		})
	}
}

func TestParsePackageJSON_Partial(t *testing.T) { // see https://github.com/anchore/syft/issues/311
	const fixtureFile = "test-fixtures/pkg-json/package-partial.json"
	fixture, err := os.Open(fixtureFile)
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	// TODO: no relationships are under test yet
	actual, _, err := parsePackageJSON("", fixture)
	if err != nil {
		t.Fatalf("failed to parse package-lock.json: %+v", err)
	}

	if actualCount := len(actual); actualCount != 0 {
		t.Errorf("no packages should've been returned (but got %d packages)", actualCount)
	}
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
