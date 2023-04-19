package source

import (
	"github.com/anchore/syft/syft/file"
)

type (
	// Deprecated: use file.Resolver instead
	FileResolver = file.Resolver

	// Deprecated: use file.ContentResolver instead
	FileContentResolver = file.ContentResolver

	// Deprecated: use file.PathResolver instead
	FilePathResolver = file.PathResolver

	// Deprecated: use file.LocationResolver instead
	FileLocationResolver = file.LocationResolver

	// Deprecated: use file.MetadataResolver instead
	FileMetadataResolver = file.MetadataResolver

	// Deprecated: use file.WritableResolver instead
	WritableFileResolver = file.WritableResolver
)
