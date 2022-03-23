package file

import (
	"io"
)

// Resolver is an interface that encompasses how to get specific file references and file contents for a generic data source.
type Resolver interface {
	ContentResolver
	PathResolver
	LocationResolver
	MetadataResolver
}

// ContentResolver knows how to get file content for a given Location
type ContentResolver interface {
	FileContentsByLocation(Location) (io.ReadCloser, error)
}

type MetadataResolver interface {
	FileMetadataByLocation(Location) (Metadata, error)
}

// PathResolver knows how to get a Location for given string paths and globs
type PathResolver interface {
	// HasPath indicates if the given path exists in the underlying source.
	HasPath(string) bool
	// FilesByPath fetches a set of file references which have the given path (for an image, there may be multiple matches)
	FilesByPath(paths ...string) ([]Location, error)
	// FilesByGlob fetches a set of file references which the given glob matches
	FilesByGlob(patterns ...string) ([]Location, error)
	// FilesByMIMEType fetches a set of file references which the contents have been classified as one of the given MIME Types
	FilesByMIMEType(types ...string) ([]Location, error)
	// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
	// This is helpful when attempting to find a file that is in the same layer or lower as another file.
	RelativeFileByPath(_ Location, path string) *Location
}

type LocationResolver interface {
	AllLocations() <-chan Location
}
