package source

import "github.com/anchore/syft/syft/file"

// Deprecated: use file.MockResolver instead
type MockResolver = file.MockResolver

// Deprecated: use file.NewMockResolver instead
func NewMockResolverForPaths(paths ...string) *MockResolver {
	return file.NewMockResolverForPaths(paths...)
}

// Deprecated: use file.NewMockResolverForPathsWithMetadata instead
func NewMockResolverForPathsWithMetadata(metadata map[Coordinates]FileMetadata) *MockResolver {
	return file.NewMockResolverForPathsWithMetadata(metadata)
}
