package pkg

import (
	"github.com/anchore/syft/syft/file"
)

// PortageMetadata represents all captured data for a Package package DB entry.
type PortageMetadata struct {
	InstalledSize int                 `mapstructure:"InstalledSize" json:"installedSize" cyclonedx:"installedSize"`
	Files         []PortageFileRecord `json:"files"`
}

// PortageFileRecord represents a single file attributed to a portage package.
type PortageFileRecord struct {
	Path   string       `json:"path"`
	Digest *file.Digest `json:"digest,omitempty"`
}
