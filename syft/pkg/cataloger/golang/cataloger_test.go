package golang

import (
	"testing"

	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_Mod_Cataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain go.mod files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"src/go.mod",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsContentQueries(test.expected).
				IgnoreUnfulfilledContentQueries("src/go.sum").
				TestCataloger(t, NewGoModFileCataloger())
		})
	}
}

func Test_Binary_Cataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain binary files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"partial-binary",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsContentQueries(test.expected).
				TestCataloger(t, NewGoModuleBinaryCataloger())
		})
	}
}
