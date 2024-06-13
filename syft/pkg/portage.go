package pkg

import (
	"github.com/anchore/syft/syft/sort"
	stdSort "sort"

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
	stdSort.Strings(result)
	return result
}

func (m PortageEntry) Compare(other PortageEntry) int {
	if i := sort.CompareOrd(m.InstalledSize, other.InstalledSize); i != 0 {
		return i
	}
	if i := sort.CompareArrays(m.Files, other.Files); i != 0 {
		return i
	}
	return 0
}

func (m PortageEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(PortageEntry); exists {
		return true, m.Compare(other)
	}
	return false, 0
}

func (m PortageFileRecord) Compare(other PortageFileRecord) int {
	if i := sort.CompareOrd(m.Path, other.Path); i != 0 {
		return i
	}
	if i := sort.ComparePtr(m.Digest, other.Digest); i != 0 {
		return i
	}
	return 0
}
