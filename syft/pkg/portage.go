package pkg

import (
	"sort"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/file"
)

var _ FileOwner = (*PortageEntry)(nil)

// PortageEntry represents a single package entry in the portage DB flat-file store.
type PortageEntry struct {
	InstalledSize int                 `mapstructure:"InstalledSize" json:"installedSize" cyclonedx:"installedSize"`
	Files         []PortageFileRecord `json:"files"`
}

// PortageFileRecord represents a single file attributed to a portage package.
type PortageFileRecord struct {
	Path   string       `json:"path"`
	Digest *file.Digest `json:"digest,omitempty"`
}

func (m PortageEntry) OwnedFiles() (result []string) {
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
