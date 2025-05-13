package pkg

type SwiplPackEntry struct {
	Name          string   `toml:"name" json:"name"`
	Version       string   `toml:"version" json:"version"`
	Author        string   `json:"author" mapstructure:"Author"`
	AuthorEmail   string   `json:"authorEmail" mapstructure:"AuthorEmail"`
	Packager      string   `json:"packager" mapstructure:"Packager"`
	PackagerEmail string   `json:"packagerEmail" mapstructure:"PackagerEmail"`
	Homepage      string   `json:"homepage"`
	Dependencies  []string `toml:"dependencies" json:"dependencies"`
}
