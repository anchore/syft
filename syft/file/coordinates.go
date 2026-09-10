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

	// FileSystemID is an ID representing an entire filesystem. For container images, this is a layer digest. For directories or a root filesystem, this is blank. A file found inside an archive carries the FileSystemID of the filesystem the archive itself was found in (a layer digest, or blank), inherited unchanged down the nesting chain; the nesting chain is carried by ArchivePath instead.
	FileSystemID string `json:"layerID,omitempty" cyclonedx:"layerID"`

	// ArchivePath is the colon-delimited chain of archive paths, from the scan root, of every archive traversed to reach this file (e.g. "app.war:WEB-INF/lib/dep.jar"). It is blank for files not found within an archive. It disambiguates identically-named files residing in different archives on the same filesystem.
	ArchivePath string `json:"archivePath,omitempty" cyclonedx:"archivePath"`
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
	if c.ArchivePath != "" {
		str += fmt.Sprintf(" Archive=%q", c.ArchivePath)
	}
	return fmt.Sprintf("Location<%s>", str)
}

func (c Coordinates) GetCoordinates() Coordinates {
	return c
}

// HashInclude controls which fields participate in the artifact ID hash (see artifact.IDByHash,
// which uses hashstructure). ArchivePath is excluded from the hash when empty so that ordinary
// (non-archive) coordinates keep the same identity they had before ArchivePath existed; a non-empty
// ArchivePath is included, which is what keeps identically-named files in different archives from
// sharing an ID.
func (c Coordinates) HashInclude(field string, _ any) (bool, error) {
	if field == "ArchivePath" && c.ArchivePath == "" {
		return false, nil
	}
	return true, nil
}
