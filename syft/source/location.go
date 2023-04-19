package source

import (
	"io"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/file"
)

type (
	Location           = file.Location
	LocationData       = file.LocationData
	LocationMetadata   = file.LocationMetadata
	LocationSet        = file.LocationSet
	Locations          = file.Locations
	LocationReadCloser = file.LocationReadCloser
)

// Deprecated: use file.NewLocationSet instead
func NewLocationSet(locations ...Location) LocationSet {
	return file.NewLocationSet(locations...)
}

// Deprecated: use file.NewLocation instead
func NewLocation(realPath string) Location {
	return file.NewLocation(realPath)
}

// Deprecated: use file.NewVirtualLocation instead
func NewVirtualLocation(realPath, virtualPath string) Location {
	return file.NewVirtualLocation(realPath, virtualPath)
}

// Deprecated: use file.NewLocationFromCoordinates instead
func NewLocationFromCoordinates(coordinates Coordinates) Location {
	return file.NewLocationFromCoordinates(coordinates)
}

// Deprecated: use file.NewVirtualLocationFromCoordinates instead
func NewVirtualLocationFromCoordinates(coordinates Coordinates, virtualPath string) Location {
	return file.NewVirtualLocationFromCoordinates(coordinates, virtualPath)
}

// Deprecated: use file.NewLocationFromImage instead
func NewLocationFromImage(virtualPath string, ref stereoscopeFile.Reference, img *image.Image) Location {
	return file.NewLocationFromImage(virtualPath, ref, img)
}

// Deprecated: use file.NewLocationFromDirectory instead
func NewLocationFromDirectory(responsePath string, ref stereoscopeFile.Reference) Location {
	return file.NewLocationFromDirectory(responsePath, ref)
}

// Deprecated: use file.NewVirtualLocationFromDirectory instead
func NewVirtualLocationFromDirectory(responsePath, virtualResponsePath string, ref stereoscopeFile.Reference) Location {
	return file.NewVirtualLocationFromDirectory(responsePath, virtualResponsePath, ref)
}

// Deprecated: use file.NewLocationReadCloser instead
func NewLocationReadCloser(location Location, reader io.ReadCloser) LocationReadCloser {
	return file.NewLocationReadCloser(location, reader)
}
