package rust

type CatalogerConfig struct {
	// Todo: find a way to replicate cargo's mapping from repository source to their repository dir name
	//		When that's done we could enable LocalModCacheDir to point to cargo's cache and read directly from there
	// SearchLocalModCacheLicenses bool   `yaml:"search-local-mod-cache-licenses" json:"search-local-mod-cache-licenses" mapstructure:"search-local-mod-cache-licenses"`
	// LocalModCacheDir            string `yaml:"local-mod-cache-dir" json:"local-mod-cache-dir" mapstructure:"local-mod-cache-dir"`
	SearchRemote bool `yaml:"search-remote" json:"search-remote" mapstructure:"search-remote"`
}

func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{
		// SearchLocalModCacheLicenses: true,
		// LocalModCacheDir:            "~/.cargo/registry",
		SearchRemote: true,
	}
}
