package pkg

import (
	"sort"

	"github.com/scylladb/go-set/strset"
)

// NixStoreEntry represents a package in the Nix store (/nix/store) with its derivation information and metadata.
type NixStoreEntry struct {
	// Path is full store path for this output (e.g. /nix/store/abc123...-package-1.0)
	Path string `mapstructure:"path" json:"path,omitempty"`

	// Output is the specific output name for multi-output packages (empty string for default "out" output, can be "bin", "dev", "doc", etc.)
	Output string `mapstructure:"output" json:"output,omitempty"`

	// OutputHash is hash prefix of the store path basename (first part before the dash)
	OutputHash string `mapstructure:"outputHash" json:"outputHash"`

	// Derivation is information about the .drv file that describes how this package was built
	Derivation NixDerivation `mapstructure:"derivation" json:"derivation,omitempty"`

	// Files are the list of files under the nix/store path for this package
	Files []string `mapstructure:"files" json:"files,omitempty"`
}

// NixDerivation represents a Nix .drv file that describes how to build a package including inputs, outputs, and build instructions.
type NixDerivation struct {
	// Path is path to the .drv file in Nix store
	Path string `mapstructure:"path" json:"path,omitempty"`

	// System is target system string indicating where derivation can be built (e.g. "x86_64-linux", "aarch64-darwin"). Must match current system for local builds.
	System string `mapstructure:"system" json:"system,omitempty"`

	// InputDerivations are the list of other derivations that were inputs to this build (dependencies)
	InputDerivations []NixDerivationReference `mapstructure:"inputDerivations" json:"inputDerivations,omitempty"`

	// InputSources are the list of source file paths that were inputs to this build
	InputSources []string `mapstructure:"inputSources" json:"inputSources,omitempty"`
}

// NixDerivationReference represents a reference to another derivation used as a build input or runtime dependency.
type NixDerivationReference struct {
	// Path is path to the referenced .drv file
	Path string `mapstructure:"path" json:"path,omitempty"`

	// Outputs are which outputs of the referenced derivation were used (e.g. ["out"], ["bin", "dev"])
	Outputs []string `mapstructure:"outputs" json:"outputs,omitempty"`
}

func (m NixStoreEntry) OwnedFiles() (result []string) {
	result = strset.New(m.Files...).List()
	sort.Strings(result)
	return
}
