package pkg

// ErlangRebarLockEntry represents a single package entry from the "deps" section within an Erlang rebar.lock file.
type ErlangRebarLockEntry struct {
	Name       string `mapstructure:"name" json:"name"`
	Version    string `mapstructure:"version" json:"version"`
	PkgHash    string `mapstructure:"pkgHash" json:"pkgHash"`
	PkgHashExt string `mapstructure:"pkgHashExt" json:"pkgHashExt"`
}
