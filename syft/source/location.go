package source

import (
	"fmt"

	"github.com/anchore/syft/internal/log"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
)

// Location represents a path relative to a particular filesystem resolved to a specific file.Reference. This struct is used as a key
// in content fetching to uniquely identify a file relative to a request (the VirtualPath).
type Location struct {
	RealPath     string         `json:"path"`              // The path where all path ancestors have no hardlinks / symlinks
	VirtualPath  string         `json:"-"`                 // The path to the file which may or may not have hardlinks / symlinks
	FileSystemID string         `json:"layerID,omitempty"` // An ID representing the filesystem. For container images this is a layer digest, directories or root filesystem this is blank.
	ref          file.Reference // The file reference relative to the stereoscope.FileCatalog that has more information about this location.
}

// NewLocation creates a new Location representing a path without denoting a filesystem or FileCatalog reference.
func NewLocation(path string) Location {
	return Location{
		RealPath: path,
	}
}

// NewLocationFromImage creates a new Location representing the given path (extracted from the ref) relative to the given image.
func NewLocationFromImage(virtualPath string, ref file.Reference, img *image.Image) Location {
	entry, err := img.FileCatalog.Get(ref)
	if err != nil {
		log.Warnf("unable to find file catalog entry for ref=%+v", ref)
		return Location{
			VirtualPath: virtualPath,
			RealPath:    string(ref.RealPath),
			ref:         ref,
		}
	}

	return Location{
		VirtualPath:  virtualPath,
		RealPath:     string(ref.RealPath),
		FileSystemID: entry.Layer.Metadata.Digest,
		ref:          ref,
	}
}

// NewLocationFromDirectory creates a new Location representing the given path (extracted from the ref) relative to the given directory.
func NewLocationFromDirectory(responsePath string, ref file.Reference) Location {
	return Location{
		RealPath: responsePath,
		ref:      ref,
	}
}

func NewLocationFromReference(ref file.Reference) Location {
	return Location{
		VirtualPath: string(ref.RealPath),
		RealPath:    string(ref.RealPath),
		ref:         ref,
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
