package pkg

type DotnetDepsMetadata struct {
	Name     string `mapstructure:"name" json:"name"`
	Version  string `mapstructure:"version" json:"version"`
	Path     string `mapstructure:"path" json:"path"`
	Sha512   string `mapstructure:"sha512" json:"sha512"`
	HashPath string `mapstructure:"hashPath" json:"hashPath"`
}
