package file

import (
	"fmt"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
)

const ArchivePathSeparator = "!/"

// Coordinates contains the minimal information needed to describe how to find a file within any possible source object (e.g. image and directory sources)
type Coordinates struct {
	// RealPath is the canonical absolute form of the path accessed (all symbolic links have been followed and relative path components like '.' and '..' have been removed). For a file found within an archive, it is the real path of the outermost archive on the scanned filesystem.
	RealPath string `json:"path" cyclonedx:"path"`

	// FileSystemID is an ID representing an entire filesystem. For container images, this is a layer digest. For directories or a root filesystem, this is blank. A file inside an archive carries the FileSystemID of the filesystem the archive was found in.
	FileSystemID string `json:"layerID,omitempty" cyclonedx:"layerID"`

	// FullPath is the full path to the file: RealPath, then for a file within an archive a "!/"-delimited chain of entry paths through any nested archives, ending with the file's own entry path (e.g. "/app.war!/WEB-INF/lib/dep.jar!/META-INF/MANIFEST.MF"). Each segment is a real path (links resolved) relative to the archive before it. For a file not within an archive it is blank, so coordinates outside archives are unchanged by the field (in JSON, equality and ID).
	FullPath string `json:"fullPath,omitempty" cyclonedx:"fullPath"`
}

// FullNestedPath is FullPath, or RealPath where FullPath is blank.
func (c Coordinates) FullNestedPath() string {
	if c.FullPath == "" {
		return c.RealPath
	}
	return c.FullPath
}

// LocalPath is the rooted path within the resolver holding the file: the last entry path in FullPath, or
// RealPath for a file not within an archive. RealPath is cut off before looking for a separator, so a
// "!/" in a real path is never taken for an archive boundary.
func (c Coordinates) LocalPath() string {
	entries, ok := strings.CutPrefix(c.FullPath, c.RealPath+ArchivePathSeparator)
	if !ok {
		return c.RealPath
	}
	if i := strings.LastIndex(entries, ArchivePathSeparator); i >= 0 {
		entries = entries[i+len(ArchivePathSeparator):]
	}
	return "/" + entries
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

	if c.FullNestedPath() != c.RealPath {
		str += fmt.Sprintf(" FullPath=%q", c.FullNestedPath())
	}
	return fmt.Sprintf("Location<%s>", str)
}

func (c Coordinates) GetCoordinates() Coordinates {
	return c
}

// HashInclude keeps a FullPath that adds nothing to RealPath out of the artifact ID hash (see
// artifact.IDByHash), so coordinates outside archives keep the IDs they had before the field existed.
func (c Coordinates) HashInclude(field string, _ any) (bool, error) {
	if field == "FullPath" && c.FullNestedPath() == c.RealPath {
		return false, nil
	}
	return true, nil
}
