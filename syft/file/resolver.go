package file

import (
	"context"
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

// MetadataResolver provides file metadata lookup by location.
type MetadataResolver interface {
	FileMetadataByLocation(Location) (Metadata, error)
}

// PathResolver knows how to get a Location for given string paths and globs
type PathResolver interface {
	// HasPath indicates if the given path exists in the underlying source.
	// The implementation for this may vary, however, generally the following considerations should be made:
	// - full symlink resolution should be performed on all requests
	// - returns locations for any file or directory
	HasPath(string) bool

	// FilesByPath fetches a set of file references which have the given path (for an image, there may be multiple matches).
	// The implementation for this may vary, however, generally the following considerations should be made:
	// - full symlink resolution should be performed on all requests
	// - only returns locations to files (NOT directories)
	FilesByPath(paths ...string) ([]Location, error)

	// FilesByGlob fetches a set of file references for the given glob matches
	// The implementation for this may vary, however, generally the following considerations should be made:
	// - full symlink resolution should be performed on all requests
	// - if multiple paths to the same file are found, the best single match should be returned
	// - only returns locations to files (NOT directories)
	FilesByGlob(patterns ...string) ([]Location, error)

	// FilesByMIMEType fetches a set of file references which the contents have been classified as one of the given MIME Types.
	FilesByMIMEType(types ...string) ([]Location, error)

	// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
	// This is helpful when attempting to find a file that is in the same layer or lower as another file.
	RelativeFileByPath(_ Location, path string) *Location
}

// LocationResolver provides iteration over all file locations in a source.
type LocationResolver interface {
	// AllLocations returns a channel of all file references from the underlying source.
	// The implementation for this may vary, however, generally the following considerations should be made:
	// - NO symlink resolution should be performed on results
	// - returns locations for any file or directory
	AllLocations(ctx context.Context) <-chan Location
}

// WritableResolver extends Resolver with the ability to write file content.
type WritableResolver interface {
	Resolver

	Write(location Location, reader io.Reader) error
}
