package internal

import (
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func GetLocationSorters(s sbom.SBOM) (func(a, b file.Location) int, func(a, b file.Coordinates) int) {
	var layers []string
	if m, ok := s.Source.Metadata.(source.ImageMetadata); ok {
		for _, l := range m.Layers {
			layers = append(layers, l.Digest)
		}
	}
	return file.LocationSorter(layers), file.CoordinatesSorter(layers)
}
