package source

import (
	"io"
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
	FileContentsByLocation(Location) (io.ReadCloser, error)
}

type FileMetadataResolver interface {
	FileMetadataByLocation(Location) (FileMetadata, error)
}

// FilePathResolver knows how to get a Location for given string paths and globs
type FilePathResolver interface {
	// HasPath indicates if the given path exists in the underlying source.
	HasPath(string) bool
	// FilesByPath fetches a set of file references which have the given path (for an image, there may be multiple matches)
	FilesByPath(paths ...string) ([]Location, error)
	// FilesByGlob fetches a set of file references for the given glob matches
	FilesByGlob(patterns ...string) ([]Location, error)
	// FilesByExtension fetches a set of file references for the given file extensions
	FilesByExtension(extensions ...string) ([]Location, error)
	// FilesByBasename fetches a set of file references for the given filenames
	FilesByBasename(basenames ...string) ([]Location, error)
	// FilesByBasenameGlob fetches a set of file references for the given filename glob patterns (e.g. *requirements*.txt)
	FilesByBasenameGlob(patterns ...string) ([]Location, error)
	// FilesByMIMEType fetches a set of file references which the contents have been classified as one of the given MIME Types
	FilesByMIMEType(types ...string) ([]Location, error)
	// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
	// This is helpful when attempting to find a file that is in the same layer or lower as another file.
	RelativeFileByPath(_ Location, path string) *Location
}

type FileLocationResolver interface {
	AllLocations() <-chan Location
}
