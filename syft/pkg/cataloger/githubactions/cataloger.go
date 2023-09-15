package githubactions

import "github.com/anchore/syft/syft/pkg/cataloger/generic"

// NewActionUsageCataloger returns GitHub Actions used within workflows or composite actions.
func NewActionUsageCataloger() *generic.Cataloger {
	return generic.NewCataloger("github-actions-usage-cataloger").
		WithParserByGlobs(parseActionsUsedInWorkflows, "**/.github/workflows/*.yaml", "**/.github/workflows/*.yml").
		WithParserByGlobs(parseActionsUsedInCompositeActions, "**/.github/actions/*/action.yml", "**/.github/actions/*/action.yaml")
}
