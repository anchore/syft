package githubactions

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
			name:      "obtain all workflow and composite action files",
			fixture:   "test-fixtures/glob",
			cataloger: NewActionUsageCataloger(),
			expected: []string{
				// composite actions
				".github/actions/bootstrap/action.yaml",
				".github/actions/unbootstrap/action.yml",
				// workflows
				".github/workflows/release.yml",
				".github/workflows/validations.yaml",
			},
		},
		{
			name:      "obtain all workflow files",
			fixture:   "test-fixtures/glob",
			cataloger: NewWorkflowUsageCataloger(),
			expected: []string{
				// workflows
				".github/workflows/release.yml",
				".github/workflows/validations.yaml",
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
