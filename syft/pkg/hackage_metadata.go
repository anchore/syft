package pkg

type HackageStackYamlLockMetadata struct {
	PkgHash     string `mapstructure:"pkgHash" json:"pkgHash,omitempty"`
	SnapshotURL string `mapstructure:"snapshotURL" json:"snapshotURL,omitempty"`
}

type HackageStackYamlMetadata struct {
	PkgHash string `mapstructure:"pkgHash" json:"pkgHash,omitempty"`
}
