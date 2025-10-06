package file

import (
	"strings"

	"github.com/anchore/syft/internal/evidence"
)

var locationSorterWithoutLayers = LocationSorter(nil)

// Locations is a sortable slice of Location values.
type Locations []Location

func (l Locations) Len() int {
	return len(l)
}

func (l Locations) Less(i, j int) bool {
	return locationSorterWithoutLayers(l[i], l[j]) < 0
}

func (l Locations) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

// LocationSorter creates a comparison function (slices.SortFunc) for Location objects based on layer order
func LocationSorter(layers []string) func(a, b Location) int { //nolint:gocognit
	var layerOrderByDigest map[string]int
	if len(layers) > 0 {
		layerOrderByDigest = make(map[string]int)
		for i, digest := range layers {
			layerOrderByDigest[digest] = i
		}
	}

	return func(a, b Location) int {
		// compare by evidence annotations first...
		aEvidence := a.Annotations[evidence.AnnotationKey]
		bEvidence := b.Annotations[evidence.AnnotationKey]

		if aEvidence != bEvidence {
			if aEvidence == evidence.PrimaryAnnotation {
				return -1
			}
			if bEvidence == evidence.PrimaryAnnotation {
				return 1
			}

			if aEvidence > bEvidence {
				return -1
			}
			if bEvidence > aEvidence {
				return 1
			}
		}

		// ...then by layer order
		if layerOrderByDigest != nil {
			// we're given layer order details
			aLayerIdx, aExists := layerOrderByDigest[a.FileSystemID]
			bLayerIdx, bExists := layerOrderByDigest[b.FileSystemID]

			if aLayerIdx != bLayerIdx {
				if !aExists && !bExists {
					return strings.Compare(a.FileSystemID, b.FileSystemID)
				}
				if !aExists {
					return 1
				}
				if !bExists {
					return -1
				}

				return aLayerIdx - bLayerIdx
			}
		} else if a.FileSystemID != b.FileSystemID {
			// no layer info given, legacy behavior is to sort lexicographically
			return strings.Compare(a.FileSystemID, b.FileSystemID)
		}

		// ...then by paths
		if a.AccessPath != b.AccessPath {
			return strings.Compare(a.AccessPath, b.AccessPath)
		}

		return strings.Compare(a.RealPath, b.RealPath)
	}
}

// CoordinatesSorter creates a comparison function (slices.SortFunc) for Coordinate objects based on layer order
func CoordinatesSorter(layers []string) func(a, b Coordinates) int {
	var layerOrderByDigest map[string]int
	if len(layers) > 0 {
		layerOrderByDigest = make(map[string]int)
		for i, digest := range layers {
			layerOrderByDigest[digest] = i
		}
	}

	return func(a, b Coordinates) int {
		// ...then by layer order
		if layerOrderByDigest != nil {
			aLayerIdx, aExists := layerOrderByDigest[a.FileSystemID]
			bLayerIdx, bExists := layerOrderByDigest[b.FileSystemID]

			if aLayerIdx != bLayerIdx {
				if !aExists && !bExists {
					return strings.Compare(a.FileSystemID, b.FileSystemID)
				}
				if !aExists {
					return 1
				}
				if !bExists {
					return -1
				}

				return aLayerIdx - bLayerIdx
			}
		}

		return strings.Compare(a.RealPath, b.RealPath)
	}
}
