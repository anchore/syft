package lua

import (
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"testing"
)

func Test_PackageCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain package files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"lua/package.rockspec",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewPackageCataloger())
		})
	}
}
