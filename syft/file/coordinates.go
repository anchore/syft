package file

import (
	"fmt"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
)

// Coordinates contains the minimal information needed to describe how to find a file within any possible source object (e.g. image and directory sources)
type Coordinates struct {
	// RealPath is the canonical absolute form of the path accessed (all symbolic links have been followed and relative path components like '.' and '..' have been removed).
	RealPath string `json:"path" cyclonedx:"path"`

	// FileSystemID is an ID representing and entire filesystem. For container images, this is a layer digest. For directories or a root filesystem, this is blank.
	FileSystemID string `json:"layerID,omitempty" cyclonedx:"layerID"`
}

func NewCoordinates(realPath, fsID string) Coordinates {
	return Coordinates{
		RealPath:     realPath,
		FileSystemID: fsID,
	}
}

func (c Coordinates) ID() artifact.ID {
	f, err := artifact.IDByHash(c)
	if err != nil {
		// TODO: what to do in this case?
		log.Debugf("unable to get fingerprint of location coordinate=%+v: %+v", c, err)
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

func (c Coordinates) GetCoordinates() Coordinates {
	return c
}
