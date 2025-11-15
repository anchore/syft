package python

// CatalogerConfig contains configuration for the python cataloger
type CatalogerConfig struct {
	// guess unpinned python package requirements
	// app-config: python.guess-unpinned-requirements
	GuessUnpinnedRequirements bool
}
