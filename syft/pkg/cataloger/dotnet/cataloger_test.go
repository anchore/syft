package dotnet

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestCataloger_Globs(t *testing.T) {
	tests := []struct {
		name      string
		fixture   string
		cataloger pkg.Cataloger
		expected  []string
	}{
		{
			name:      "obtain deps.json files",
			fixture:   "test-fixtures/glob-paths",
			cataloger: NewDotnetDepsCataloger(),
			expected: []string{
				"src/something.deps.json",
			},
		},
		{
			name:      "obtain portable executable files",
			fixture:   "test-fixtures/glob-paths",
			cataloger: NewDotnetPortableExecutableCataloger(),
			expected: []string{
				"src/something.dll",
				"src/something.exe",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, test.cataloger)
		})
	}
}
