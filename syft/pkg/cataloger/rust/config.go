package rust

type CatalogerConfig struct {
	SearchRemoteLicenses bool   `json:"search-remote-licenses" yaml:"search-remote-licenses" mapstructure:"search-remote-licenses"`
	Proxy                string `yaml:"proxy,omitempty" json:"proxy,omitempty" mapstructure:"proxy"`
}

// DefaultCatalogerConfig create a CatalogerConfig with default options, which includes:
// SearchRemoteLicenses: false
// Proxy: GOPROXY
func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{
		SearchRemoteLicenses: false,
		Proxy:                "",
	}
}
