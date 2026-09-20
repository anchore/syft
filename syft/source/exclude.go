package source

type ExcludeConfig struct {
	Paths []string
}

// PathExcluder is optionally implemented by a source configured with path exclusion patterns. It
// publishes them so a consumer that indexes source content as its own filesystem can honor the scan's
// exclusions without a second setting. The nested archive cataloger is that consumer: it indexes every
// archive independently. All patterns are published; which are depth-independent enough to be
// meaningful is the consumer's business.
//
// Implementations must return a copy: sources that build directory resolvers pass their patterns to
// GetDirectoryExclusionFunctions, which rewrites them absolute against the scan root.
type PathExcluder interface {
	ExcludedPaths() []string
}
