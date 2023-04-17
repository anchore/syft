package pkg

import (
	"sort"

	"github.com/scylladb/go-set/strset"
)

type NixStoreMetadata struct {
	// OutputHash is the prefix of the nix store basename path
	OutputHash string `mapstructure:"outputHash" json:"outputHash"`

	// Output allows for optionally specifying the specific nix package output this package represents (for packages that support multiple outputs).
	// Note: the default output for a package is an empty string, so will not be present in the output.
	Output string `mapstructure:"output" json:"output,omitempty"`

	// Files is a listing a files that are under the nix/store path for this package
	Files []string `mapstructure:"files" json:"files"`
}

func (m NixStoreMetadata) OwnedFiles() (result []string) {
	result = strset.New(m.Files...).List()
	sort.Strings(result)
	return
}
