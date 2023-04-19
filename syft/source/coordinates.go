package source

import (
	"github.com/anchore/syft/syft/file"
)

type Coordinates = file.Coordinates
type CoordinateSet = file.CoordinateSet

// Deprecated: use file.NewCoordinateSet instead
func NewCoordinateSet(coordinates ...Coordinates) CoordinateSet {
	return file.NewCoordinateSet(coordinates...)
}
