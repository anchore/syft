package dotnet

import (
	"testing"

	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain deps.json files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"src/something.deps.json",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsContentQueries(test.expected).
				TestCataloger(t, NewDotnetDepsCataloger())
		})
	}
}
