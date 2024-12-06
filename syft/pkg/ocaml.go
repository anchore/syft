package pkg

type OpamPackage struct {
	Name         string   `toml:"name" json:"name"`
	Version      string   `toml:"version" json:"version"`
	Licenses     []string `mapstructure:"licenses" json:"licenses"`
	URL          string   `mapstructure:"url" json:"url"`
	Checksums    []string `mapstructure:"checksums" json:"checksum"`
	Homepage     string   `json:"homepage"`
	Dependencies []string `toml:"dependencies" json:"dependencies"`
}
