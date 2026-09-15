package source

type ExcludeConfig struct {
	Paths []string
}

// PathExcluder is optionally implemented by a source that was configured with path exclusion
// patterns. It publishes those patterns so that a consumer which indexes content taken from the
// source as a filesystem of its own can honor the scan's exclusions rather than carry a second
// setting for the same purpose. The nested archive cataloger is that consumer: every archive it
// finds is extracted to a directory and indexed independently, and a pattern the scan excluded
// would otherwise be read inside an archive after being skipped outside one.
//
// Only patterns whose own shape is depth-independent are meaningful to such a consumer; a pattern
// anchored to the scan root describes a layout that exists only there. Deciding that is the
// consumer's business, so everything the source was given is published here.
//
// Implementations MUST return a copy. Sources that build directory resolvers hand their patterns to
// GetDirectoryExclusionFunctions, which rewrites what it is given to be absolute against the scan
// root, so a caller holding the same slice would find the patterns replaced the moment the source
// built its resolver.
type PathExcluder interface {
	ExcludedPaths() []string
}
