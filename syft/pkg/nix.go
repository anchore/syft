package pkg

import (
	"github.com/anchore/syft/syft/sort"
	"github.com/scylladb/go-set/strset"
	stdSort "sort"
)

type NixStoreEntry struct {
	// OutputHash is the prefix of the nix store basename path
	OutputHash string `mapstructure:"outputHash" json:"outputHash"`

	// Output allows for optionally specifying the specific nix package output this package represents (for packages that support multiple outputs).
	// Note: the default output for a package is an empty string, so will not be present in the output.
	Output string `mapstructure:"output" json:"output,omitempty"`

	// Files is a listing a files that are under the nix/store path for this package
	Files []string `mapstructure:"files" json:"files"`
}

func (m NixStoreEntry) OwnedFiles() (result []string) {
	result = strset.New(m.Files...).List()
	stdSort.Strings(result)
	return
}
func (m NixStoreEntry) Compare(other NixStoreEntry) int {
	if i := sort.CompareOrd(m.OutputHash, other.OutputHash); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Output, other.Output); i != 0 {
		return i
	}
	return sort.CompareArraysOrd(m.Files, other.Files)
}
func (m NixStoreEntry) TryCompare(other any) (bool, int) {
	if otherNix, exists := other.(NixStoreEntry); exists {
		return true, m.Compare(otherNix)
	}
	return false, 0
}
