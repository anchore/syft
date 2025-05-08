package pkg

import (
	"sort"

	"github.com/scylladb/go-set/strset"
)

type NixStoreEntry struct {
	// Path is the store path for this output
	Path string `mapstructure:"path" json:"path,omitempty"`

	// Output allows for optionally specifying the specific nix package output this package represents (for packages that support multiple outputs).
	// Note: the default output for a package is an empty string, so will not be present in the output.
	Output string `mapstructure:"output" json:"output,omitempty"`

	// OutputHash is the prefix of the nix store basename path
	OutputHash string `mapstructure:"outputHash" json:"outputHash"`

	// Derivation is any information about the derivation file that was used to build this package
	Derivation NixDerivation `mapstructure:"derivation" json:"derivation,omitempty"`

	// Files is a listing a files that are under the nix/store path for this package
	Files []string `mapstructure:"files" json:"files,omitempty"`
}

type NixDerivation struct {
	// Path is the path to the derivation file
	Path string `mapstructure:"path" json:"path,omitempty"`

	// System is the nix system string that this derivation was built for
	System string `mapstructure:"system" json:"system,omitempty"`

	// InputDerivations is a list of derivation paths that were used to build this package
	InputDerivations []NixDerivationReference `mapstructure:"inputDerivations" json:"inputDerivations,omitempty"`

	// InputSources is a list of source paths that were used to build this package
	InputSources []string `mapstructure:"inputSources" json:"inputSources,omitempty"`
}

type NixDerivationReference struct {
	// Path is the path to the derivation file
	Path string `mapstructure:"path" json:"path,omitempty"`

	// Outputs is a list of output names that were used to build this package
	Outputs []string `mapstructure:"outputs" json:"outputs,omitempty"`
}

func (m NixStoreEntry) OwnedFiles() (result []string) {
	result = strset.New(m.Files...).List()
	sort.Strings(result)
	return
}
