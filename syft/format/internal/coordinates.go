package internal

import (
	"strings"

	"github.com/anchore/syft/syft/file"
)

// NormalizeCoordinates clears a decoded FullPath that adds no archive chain to RealPath (one equal to
// RealPath, or one not starting with RealPath and "!/"), so decoded coordinates compare equal to the
// ones a resolver builds.
func NormalizeCoordinates(c file.Coordinates) file.Coordinates {
	if !strings.HasPrefix(c.FullPath, c.RealPath+file.ArchivePathSeparator) {
		c.FullPath = ""
	}
	return c
}

// NormalizeLocations applies NormalizeCoordinates to each location in place.
func NormalizeLocations(locations []file.Location) []file.Location {
	for i := range locations {
		locations[i].Coordinates = NormalizeCoordinates(locations[i].Coordinates)
	}
	return locations
}
