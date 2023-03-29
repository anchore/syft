package pkg

import (
	"github.com/anchore/syft/syft/file"
	"github.com/scylladb/go-set/strset"
	"sort"
)

var _ FileOwner = (*PortageMetadata)(nil)

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

func (m PortageMetadata) OwnedFiles() (result []string) {
	s := strset.New()
	for _, f := range m.Files {
		if f.Path != "" {
			s.Add(f.Path)
		}
	}
	result = s.List()
	sort.Strings(result)
	return result
}
