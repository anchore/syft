package pkg

import (
	"github.com/scylladb/go-set/strset"
	"sort"
)

type NixStoreMetadata struct {
	// Hash is the prefix of the nix store basename path
	Hash string `mapstructure:"hash" json:"hash"`

	// Output allows for optionally specifying the specific nix package output this package represents (for packages that support multiple outputs)
	Output string `mapstructure:"output" json:"output,omitempty"`

	// Files is a listing a files that are under the nix/store path for this package
	Files []string `mapstructure:"files" json:"files,omitempty"`
}

func (m NixStoreMetadata) OwnedFiles() (result []string) {
	result = strset.New(m.Files...).List()
	sort.Strings(result)
	return
}
