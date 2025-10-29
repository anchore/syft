package pkg

// GitHubActionsUseStatement represents a single 'uses' statement in a GitHub Actions workflow file referencing an action or reusable workflow.
type GitHubActionsUseStatement struct {
	// Value is the action reference (e.g. "actions/checkout@v3")
	Value string `json:"value"`

	// Comment is the inline comment associated with this uses statement
	Comment string `json:"comment,omitempty"`
}
