package githubactions

import "github.com/anchore/syft/syft/pkg/cataloger/generic"

// NewActionUsageCataloger returns GitHub Actions used within workflows and composite actions.
func NewActionUsageCataloger() *generic.Cataloger {
	return generic.NewCataloger("github-actions-usage-cataloger").
		WithParserByGlobs(parseWorkflowForActionUsage, "**/.github/workflows/*.yaml", "**/.github/workflows/*.yml").
		WithParserByGlobs(parseCompositeActionForActionUsage, "**/.github/actions/*/action.yml", "**/.github/actions/*/action.yaml")
}

// NewWorkflowUsageCataloger returns shared workflows used within workflows.
func NewWorkflowUsageCataloger() *generic.Cataloger {
	return generic.NewCataloger("github-action-workflow-usage-cataloger").
		WithParserByGlobs(parseWorkflowForWorkflowUsage, "**/.github/workflows/*.yaml", "**/.github/workflows/*.yml")
}
