package pkg

type SwiplPackEntry struct {
	Name          string   `toml:"name" json:"name"`
	Version       string   `toml:"version" json:"version"`
	Author        string   `json:"author" mapstructure:"Author"`
	AuthorEmail   string   `json:"authorEmail" mapstructure:"Authoremail"`
	Packager      string   `json:"packager" mapstructure:"Packager"`
	PackagerEmail string   `json:"packagerEmail" mapstructure:"Packageremail"`
	Homepage      string   `json:"homepage"`
	Dependencies  []string `toml:"dependencies" json:"dependencies"`
}
