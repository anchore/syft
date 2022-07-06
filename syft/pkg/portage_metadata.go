package pkg

import (
	"github.com/anchore/syft/syft/file"
)

const PortageDBGlob = "**/var/db/pkg/*/*/CONTENTS"

// PortageMetadata represents all captured data for a Package package DB entry.
type PortageMetadata struct {
	Package       string              `mapstructure:"Package" json:"package"`
	Version       string              `mapstructure:"Version" json:"version"`
	InstalledSize int                 `mapstructure:"InstalledSize" json:"installedSize" cyclonedx:"installedSize"`
	Files         []PortageFileRecord `json:"files"`
}

// PortageFileRecord represents a single file attributed to a portage package.
type PortageFileRecord struct {
	Path   string       `json:"path"`
	Digest *file.Digest `json:"digest,omitempty"`
}
