package pkg

type SwiplPackEntry struct {
	Name          string   `toml:"name" json:"name"`
	Version       string   `toml:"version" json:"version"`
	Author        string   `json:"author" mapstruct:"Author"`
	AuthorEmail   string   `json:"authorEmail" mapstruct:"Authoremail"`
	Packager      string   `json:"packager" mapstructure:"Packager"`
	PackagerEmail string   `json:"packagerEmail" mapstruct:"Packageremail"`
	Homepage      string   `json:"homepage"`
	Dependencies  []string `toml:"dependencies" json:"dependencies"`
}
