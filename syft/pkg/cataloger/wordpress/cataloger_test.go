package wordpress

import (
	"testing"

	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_WordpressPlugin_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain wordpress plugin files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"wp-content/plugins/akismet/akismet.php",
				"wp-content/plugins/all-in-one-wp-migration/all-in-one-wp-migration.php",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewWordpressPluginCataloger())
		})
	}
}
