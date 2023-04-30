package source

import (
	"io"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/file"
)

// Deprecated: use file.Metadata instead
type FileMetadata = file.Metadata

type (
	// Deprecated: use file.Coordinates instead
	Coordinates = file.Coordinates

	// Deprecated: use file.CoordinateSet instead
	CoordinateSet = file.CoordinateSet

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

	// Deprecated: use file.MockResolver instead
	MockResolver = file.MockResolver

	// Deprecated: use file.Location instead
	Location = file.Location

	// Deprecated: use file.LocationData instead
	LocationData = file.LocationData

	// Deprecated: use file.LocationMetadata instead
	LocationMetadata = file.LocationMetadata

	// Deprecated: use file.LocationSet instead
	LocationSet = file.LocationSet

	// Deprecated: use file.Locations instead
	Locations = file.Locations

	// Deprecated: use file.LocationReadCloser instead
	LocationReadCloser = file.LocationReadCloser
)

// Deprecated: use file.NewCoordinateSet instead
func NewCoordinateSet(coordinates ...file.Coordinates) file.CoordinateSet {
	return file.NewCoordinateSet(coordinates...)
}

// Deprecated: use file.NewLocationSet instead
func NewLocationSet(locations ...file.Location) file.LocationSet {
	return file.NewLocationSet(locations...)
}

// Deprecated: use file.NewLocation instead
func NewLocation(realPath string) file.Location {
	return file.NewLocation(realPath)
}

// Deprecated: use file.NewVirtualLocation instead
func NewVirtualLocation(realPath, virtualPath string) file.Location {
	return file.NewVirtualLocation(realPath, virtualPath)
}

// Deprecated: use file.NewLocationFromCoordinates instead
func NewLocationFromCoordinates(coordinates file.Coordinates) file.Location {
	return file.NewLocationFromCoordinates(coordinates)
}

// Deprecated: use file.NewVirtualLocationFromCoordinates instead
func NewVirtualLocationFromCoordinates(coordinates file.Coordinates, virtualPath string) file.Location {
	return file.NewVirtualLocationFromCoordinates(coordinates, virtualPath)
}

// Deprecated: use file.NewLocationFromImage instead
func NewLocationFromImage(virtualPath string, ref stereoscopeFile.Reference, img *image.Image) file.Location {
	return file.NewLocationFromImage(virtualPath, ref, img)
}

// Deprecated: use file.NewLocationFromDirectory instead
func NewLocationFromDirectory(responsePath string, ref stereoscopeFile.Reference) file.Location {
	return file.NewLocationFromDirectory(responsePath, ref)
}

// Deprecated: use file.NewVirtualLocationFromDirectory instead
func NewVirtualLocationFromDirectory(responsePath, virtualResponsePath string, ref stereoscopeFile.Reference) file.Location {
	return file.NewVirtualLocationFromDirectory(responsePath, virtualResponsePath, ref)
}

// Deprecated: use file.NewLocationReadCloser instead
func NewLocationReadCloser(location file.Location, reader io.ReadCloser) file.LocationReadCloser {
	return file.NewLocationReadCloser(location, reader)
}

// Deprecated: use file.NewMockResolverForPaths instead
func NewMockResolverForPaths(paths ...string) *file.MockResolver {
	return file.NewMockResolverForPaths(paths...)
}

// Deprecated: use file.NewMockResolverForPathsWithMetadata instead
func NewMockResolverForPathsWithMetadata(metadata map[file.Coordinates]file.Metadata) *file.MockResolver {
	return file.NewMockResolverForPathsWithMetadata(metadata)
}
