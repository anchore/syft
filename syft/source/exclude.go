package source

type ExcludeConfig struct {
	Paths                []string
	ExcludeFile          string
	ExcludeGitignoreMode string
}

// PathExcluder is implemented by a source configured with path exclusion patterns, so the archive
// cataloger can apply the same exclusions inside the archives it extracts.
type PathExcluder interface {
	ExcludedPaths() []string
}
