package source

import (
	"io"

	"github.com/anchore/syft/syft/file"
)

// FileResolver is an interface that encompasses how to get specific file references and file contents for a generic data source.
type FileResolver interface {
	FileContentResolver
	FilePathResolver
	FileLocationResolver
	FileMetadataResolver
}

// FileContentResolver knows how to get file content for a given Location
type FileContentResolver interface {
	FileContentsByLocation(file.Location) (io.ReadCloser, error)
}

type FileMetadataResolver interface {
	FileMetadataByLocation(file.Location) (file.Metadata, error)
}

// FilePathResolver knows how to get a Location for given string paths and globs
type FilePathResolver interface {
	// HasPath indicates if the given path exists in the underlying source.
	HasPath(string) bool
	// FilesByPath fetches a set of file references which have the given path (for an image, there may be multiple matches)
	FilesByPath(paths ...string) ([]file.Location, error)
	// FilesByGlob fetches a set of file references which the given glob matches
	FilesByGlob(patterns ...string) ([]file.Location, error)
	// FilesByMIMEType fetches a set of file references which the contents have been classified as one of the given MIME Types
	FilesByMIMEType(types ...string) ([]file.Location, error)
	// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
	// This is helpful when attempting to find a file that is in the same layer or lower as another file.
	RelativeFileByPath(_ file.Location, path string) *file.Location
}

type FileLocationResolver interface {
	AllLocations() <-chan file.Location
}
