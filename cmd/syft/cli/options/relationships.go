package options

type relationshipsConfig struct {
	PackageFileOwnership        bool `mapstructure:"package-file-ownership" json:"package-file-ownership" yaml:"package-file-ownership"`
	PackageFileOwnershipOverlap bool `mapstructure:"package-file-ownership-overlap" json:"package-file-ownership-overlap" yaml:"package-file-ownership-overlap"`
}

func defaultRelationshipsConfig() relationshipsConfig {
	return relationshipsConfig{
		PackageFileOwnership:        true,
		PackageFileOwnershipOverlap: true,
	}
}
