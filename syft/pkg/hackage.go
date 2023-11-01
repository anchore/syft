package pkg

// HackageStackYamlLockEntry represents a single entry from the "packages" section of a stack.yaml.lock file.
type HackageStackYamlLockEntry struct {
	PkgHash     string `mapstructure:"pkgHash" json:"pkgHash,omitempty"`
	SnapshotURL string `mapstructure:"snapshotURL" json:"snapshotURL,omitempty"`
}

// HackageStackYamlEntry represents a single entry from the "extra-deps" section of a stack.yaml file.
type HackageStackYamlEntry struct {
	PkgHash string `mapstructure:"pkgHash" json:"pkgHash,omitempty"`
}
