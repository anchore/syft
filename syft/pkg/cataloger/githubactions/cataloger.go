package githubactions

import "github.com/anchore/syft/syft/pkg/cataloger/generic"

// NewUsageCataloger returns GitHub Actions and shared workflows used within workflows and composite actions.
func NewUsageCataloger() *generic.Cataloger {
	return generic.NewCataloger("github-actions-usage-cataloger").
		WithParserByGlobs(parseWorkflow, "**/.github/workflows/*.yaml", "**/.github/workflows/*.yml").
		WithParserByGlobs(parseCompositeActions, "**/.github/actions/*/action.yml", "**/.github/actions/*/action.yaml")
}
