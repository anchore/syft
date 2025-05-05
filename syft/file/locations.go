package file

import (
	"sort"

	"github.com/anchore/syft/internal/evidence"
)

type Locations []Location

func (l Locations) Len() int {
	return len(l)
}

func (l Locations) Less(i, j int) bool {
	liEvidence := l[i].Annotations[evidence.AnnotationKey]
	ljEvidence := l[j].Annotations[evidence.AnnotationKey]
	if liEvidence == ljEvidence {
		if l[i].RealPath == l[j].RealPath {
			if l[i].AccessPath == l[j].AccessPath {
				return l[i].FileSystemID < l[j].FileSystemID
			}
			return l[i].AccessPath < l[j].AccessPath
		}
		return l[i].RealPath < l[j].RealPath
	}
	if liEvidence == evidence.PrimaryAnnotation {
		return true
	}
	if ljEvidence == evidence.PrimaryAnnotation {
		return false
	}

	return liEvidence > ljEvidence
}

func (l Locations) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

type locationsByContainerOrder struct {
	locations          []Location
	layerOrderByDigest map[string]int
}

func LocationsByContainerOrder(locations []Location, layerOrderByDigest map[string]int) sort.Interface {
	if layerOrderByDigest == nil {
		return Locations{}
	}
	return locationsByContainerOrder{
		locations:          locations,
		layerOrderByDigest: layerOrderByDigest,
	}
}

func (l locationsByContainerOrder) Len() int {
	return len(l.locations)
}

func (l locationsByContainerOrder) Less(i, j int) bool {
	// sort by primary evidence first, supporting evidence second, then no evidence third
	// with each evidence group sorted by layer order, then by access path, then by real path
	liEvidence := l.locations[i].Annotations[evidence.AnnotationKey]
	ljEvidence := l.locations[j].Annotations[evidence.AnnotationKey]
	if liEvidence == ljEvidence {
		iLayer, jLayer := l.layerOrderByDigest[l.locations[i].FileSystemID], l.layerOrderByDigest[l.locations[j].FileSystemID]

		if iLayer == jLayer {
			if l.locations[i].AccessPath == l.locations[j].AccessPath {
				return l.locations[i].RealPath < l.locations[j].RealPath
			}
			return l.locations[i].AccessPath < l.locations[j].AccessPath
		}
		return iLayer < jLayer
	}
	if liEvidence == evidence.PrimaryAnnotation {
		return true
	}
	if ljEvidence == evidence.PrimaryAnnotation {
		return false
	}

	return liEvidence > ljEvidence
}

func (l locationsByContainerOrder) Swap(i, j int) {
	l.locations[i], l.locations[j] = l.locations[j], l.locations[i]
}
