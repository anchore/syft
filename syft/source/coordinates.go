package source

import (
	"fmt"
	"sort"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
)

// Coordinates contains the minimal information needed to describe how to find a file within any possible source object (e.g. image and directory sources)
type Coordinates struct {
	RealPath     string `json:"path"`              // The path where all path ancestors have no hardlinks / symlinks
	FileSystemID string `json:"layerID,omitempty"` // An ID representing the filesystem. For container images, this is a layer digest. For directories or a root filesystem, this is blank.
}

// CoordinateSet represents a set of string types.
type CoordinateSet map[Coordinates]struct{}

// NewCoordinateSet creates a CoordinateSet populated with values from the given slice.
func NewCoordinateSet(start ...Coordinates) CoordinateSet {
	ret := make(CoordinateSet)
	for _, s := range start {
		ret.Add(s)
	}
	return ret
}

func (c Coordinates) ID() artifact.ID {
	f, err := artifact.IDFromHash(c)
	if err != nil {
		// TODO: what to do in this case?
		log.Warnf("unable to get fingerprint of location coordinate=%+v: %+v", c, err)
		return ""
	}

	return f
}

func (c Coordinates) String() string {
	str := fmt.Sprintf("RealPath=%q", c.RealPath)

	if c.FileSystemID != "" {
		str += fmt.Sprintf(" Layer=%q", c.FileSystemID)
	}
	return fmt.Sprintf("Location<%s>", str)
}

// Add a string to the set.
func (s CoordinateSet) Add(i Coordinates) {
	s[i] = struct{}{}
}

// Remove a string from the set.
func (s CoordinateSet) Remove(i Coordinates) {
	delete(s, i)
}

// Contains indicates if the given string is contained within the set.
func (s CoordinateSet) Contains(i Coordinates) bool {
	_, ok := s[i]
	return ok
}

// ToSlice returns a sorted slice of Locations that are contained within the set.
func (s CoordinateSet) ToSlice() []Coordinates {
	ret := make([]Coordinates, len(s))
	idx := 0
	for v := range s {
		ret[idx] = v
		idx++
	}

	sort.SliceStable(ret, func(i, j int) bool {
		if ret[i].RealPath == ret[j].RealPath {
			return ret[i].FileSystemID < ret[j].FileSystemID
		}
		return ret[i].RealPath < ret[j].RealPath
	})
	return ret
}
