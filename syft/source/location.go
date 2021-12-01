package source

import (
	"fmt"

	"github.com/mitchellh/hashstructure/v2"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/internal/log"
)

var _ hashstructure.Hashable = (*Location)(nil)

// Location represents a path relative to a particular filesystem resolved to a specific file.Reference. This struct is used as a key
// in content fetching to uniquely identify a file relative to a request (the VirtualPath).
type Location struct {
	Coordinates
	VirtualPath string         // The path to the file which may or may not have hardlinks / symlinks
	ref         file.Reference // The file reference relative to the stereoscope.FileCatalog that has more information about this location.
}

// NewLocation creates a new Location representing a path without denoting a filesystem or FileCatalog reference.
func NewLocation(realPath string) Location {
	return Location{
		Coordinates: Coordinates{
			RealPath: realPath,
		},
	}
}

// NewVirtualLocation creates a new location for a path accessed by a virtual path (a path with a symlink or hardlink somewhere in the path)
func NewVirtualLocation(realPath, virtualPath string) Location {
	return Location{
		Coordinates: Coordinates{
			RealPath: realPath,
		},
		VirtualPath: virtualPath,
	}
}

// NewLocationFromCoordinates creates a new location for the given Coordinates.
func NewLocationFromCoordinates(coordinates Coordinates) Location {
	return Location{
		Coordinates: coordinates,
	}
}

// NewLocationFromImage creates a new Location representing the given path (extracted from the ref) relative to the given image.
func NewLocationFromImage(virtualPath string, ref file.Reference, img *image.Image) Location {
	entry, err := img.FileCatalog.Get(ref)
	if err != nil {
		log.Warnf("unable to find file catalog entry for ref=%+v", ref)
		return Location{
			Coordinates: Coordinates{
				RealPath: string(ref.RealPath),
			},
			VirtualPath: virtualPath,
			ref:         ref,
		}
	}

	return Location{
		Coordinates: Coordinates{
			RealPath:     string(ref.RealPath),
			FileSystemID: entry.Layer.Metadata.Digest,
		},
		VirtualPath: virtualPath,
		ref:         ref,
	}
}

// NewLocationFromDirectory creates a new Location representing the given path (extracted from the ref) relative to the given directory.
func NewLocationFromDirectory(responsePath string, ref file.Reference) Location {
	return Location{
		Coordinates: Coordinates{
			RealPath: responsePath,
		},
		ref: ref,
	}
}

func (l Location) String() string {
	str := ""
	if l.ref.ID() != 0 {
		str += fmt.Sprintf("id=%d ", l.ref.ID())
	}

	str += fmt.Sprintf("RealPath=%q", l.RealPath)

	if l.VirtualPath != "" {
		str += fmt.Sprintf(" VirtualPath=%q", l.VirtualPath)
	}

	if l.FileSystemID != "" {
		str += fmt.Sprintf(" Layer=%q", l.FileSystemID)
	}
	return fmt.Sprintf("Location<%s>", str)
}

func (l Location) Hash() (uint64, error) {
	// since location is part of the package definition it is important that only coordinates are used during object
	// hashing. (Location hash should be a pass-through for the coordinates and not include ref or VirtualPath.)
	return hashstructure.Hash(l.ID(), hashstructure.FormatV2, nil)
}
