package elixir

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
			name:    "obtain mix.lock files",
			fixture: "testdata/glob-paths",
			expected: []string{
				"src/mix.lock",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewMixLockCataloger())
		})
	}
}

func TestCataloger_Relationships(t *testing.T) {
	expectedRelationships := []string{
		"cowlib @ 2.11.0 (mix.lock) [dependency-of] cowboy @ 2.9.0 (mix.lock)",
		"ranch @ 1.8.0 (mix.lock) [dependency-of] cowboy @ 2.9.0 (mix.lock)",
	}

	pkgtest.NewCatalogTester().
		FromDirectory(t, "testdata/relationships").
		ExpectsRelationshipStrings(expectedRelationships).
		TestCataloger(t, NewMixLockCataloger())
}
