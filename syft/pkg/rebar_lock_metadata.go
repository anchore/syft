package pkg

type RebarLockMetadata struct {
	Name       string `mapstructure:"name" json:"name"`
	Version    string `mapstructure:"version" json:"version"`
	PkgHash    string `mapstructure:"pkgHash" json:"pkgHash"`
	PkgHashExt string `mapstructure:"pkgHashExt" json:"pkgHashExt"`
}
