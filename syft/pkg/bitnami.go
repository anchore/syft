package pkg

// BitnamiSBOMEntry represents all captured data from Bitnami packages
// described in Bitnami' SPDX files.
type BitnamiSBOMEntry struct {
	// Name is the package name as found in the Bitnami SPDX file
	Name string `mapstructure:"name" json:"name"`

	// Architecture is the target CPU architecture (amd64 or arm64 in Bitnami images)
	Architecture string `mapstructure:"arch" json:"arch"`

	// Distro is the distribution name this package is for (base OS like debian, ubuntu, etc.)
	Distro string `mapstructure:"distro" json:"distro"`

	// Revision is the Bitnami-specific package revision number (incremented for Bitnami rebuilds of same upstream version)
	Revision string `mapstructure:"revision" json:"revision"`

	// Version is the package version as found in the Bitnami SPDX file
	Version string `mapstructure:"version" json:"version"`

	// Path is the installation path in the filesystem where the package is located
	Path string `mapstructure:"path" json:"path"`

	// Files are the file paths owned by this package (tracked via SPDX relationships)
	Files []string `mapstructure:"files" json:"files"`
}

func (b BitnamiSBOMEntry) OwnedFiles() (result []string) {
	return b.Files
}
