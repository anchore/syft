package source

import (
	"github.com/anchore/syft/internal/log"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
)

// Location represents a path relative to a particular filesystem.
type Location struct {
	Path         string         `json:"path"`              // The string path of the location (e.g. /etc/hosts)
	FileSystemID string         `json:"layerID,omitempty"` // An ID representing the filesystem. For container images this is a layer digest, directories or root filesystem this is blank.
	ref          file.Reference // The file reference relative to the stereoscope.FileCatalog that has more information about this location.
}

// NewLocation creates a new Location representing a path without denoting a filesystem or FileCatalog reference.
func NewLocation(path string) Location {
	return Location{
		Path: path,
	}
}

// NewLocationFromImage creates a new Location representing the given path (extracted from the ref) relative to the given image.
func NewLocationFromImage(ref file.Reference, img *image.Image) Location {
	entry, err := img.FileCatalog.Get(ref)
	if err != nil {
		log.Warnf("unable to find file catalog entry for ref=%+v", ref)
		return Location{
			Path: string(ref.RealPath),
			ref:  ref,
		}
	}

	return Location{
		Path:         string(ref.RealPath),
		FileSystemID: entry.Layer.Metadata.Digest,
		ref:          ref,
	}
}
