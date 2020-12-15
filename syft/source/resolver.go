package source

import (
	"fmt"
	"io"

	"github.com/anchore/stereoscope/pkg/image"
)

// Resolver is an interface that encompasses how to get specific file references and file contents for a generic data source.
type Resolver interface {
	ContentResolver
	FileResolver
}

// ContentResolver knows how to get file content for given file.References
type ContentResolver interface {
	FileContentsByLocation(Location) (io.ReadCloser, error)
	MultipleFileContentsByLocation([]Location) (map[Location]io.ReadCloser, error)
	// TODO: we should consider refactoring to return a set of io.Readers or file.Openers instead of the full contents themselves (allow for optional buffering).
}

// FileResolver knows how to get file.References for given string paths and globs
type FileResolver interface {
	// FilesByPath fetches a set of file references which have the given path (for an image, there may be multiple matches)
	FilesByPath(paths ...string) ([]Location, error)
	// FilesByGlob fetches a set of file references which the given glob matches
	FilesByGlob(patterns ...string) ([]Location, error)
	// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
	// This is helpful when attempting to find a file that is in the same layer or lower as another file.
	RelativeFileByPath(_ Location, path string) *Location
}

// getImageResolver returns the appropriate resolve for a container image given the source option
func getImageResolver(img *image.Image, scope Scope) (Resolver, error) {
	switch scope {
	case SquashedScope:
		return NewImageSquashResolver(img)
	case AllLayersScope:
		return NewAllLayersResolver(img)
	default:
		return nil, fmt.Errorf("bad scope provided: %+v", scope)
	}
}
