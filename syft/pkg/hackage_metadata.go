package pkg

type HackageMetadata struct {
	Name        string `mapstructure:"name" json:"name"`
	Version     string `mapstructure:"version" json:"version"`
	PkgHash     string `mapstructure:"pkgHash" json:"pkgHash,omitempty"`
	SnapshotURL string `mapstructure:"snapshotURL" json:"snapshotURL,omitempty"`
}
