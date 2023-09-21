package options

type golang struct {
	SearchLocalModCacheLicenses bool   `json:"search-local-mod-cache-licenses" yaml:"search-local-mod-cache-licenses" mapstructure:"search-local-mod-cache-licenses"`
	LocalModCacheDir            string `json:"local-mod-cache-dir" yaml:"local-mod-cache-dir" mapstructure:"local-mod-cache-dir"`
	SearchRemoteLicenses        bool   `json:"search-remote-licenses" yaml:"search-remote-licenses" mapstructure:"search-remote-licenses"`
	Proxy                       string `json:"proxy" yaml:"proxy" mapstructure:"proxy"`
	NoProxy                     string `json:"no-proxy" yaml:"no-proxy" mapstructure:"no-proxy"`
}
