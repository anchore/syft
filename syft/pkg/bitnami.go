package pkg

// BitnamiEntry represents all captured data from Bitnami packages
// described in Bitnami' SPDX files.
type BitnamiEntry struct {
	Name         string `mapstructure:"name" json:"name"`
	Architecture string `mapstructure:"arch" json:"arch"`
	Distro       string `mapstructure:"distro" json:"distro"`
	Revision     string `mapstructure:"revision" json:"revision"`
	Version      string `mapstructure:"version" json:"version"`
	Path         string `mapstructure:"path" json:"path"`
}

func (b BitnamiEntry) OwnedFiles() (result []string) {
	return []string{
		b.Path,
	}
}
