package source

type ExcludeConfig struct {
	Paths []string
}

// PathExcluder is implemented by a source configured with path exclusion patterns, so the archive
// cataloger can apply the same exclusions inside the archives it extracts.
type PathExcluder interface {
	ExcludedPaths() []string
}
