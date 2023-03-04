package haskell

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
			name:    "obtain stack and cabal files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"src/stack.yaml",
				"src/stack.yaml.lock",
				"src/cabal.project.freeze",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewHackageCataloger())
		})
	}
}
