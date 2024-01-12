package cataloging

type RelationshipsConfig struct {
	PackageFileOwnership                          bool `yaml:"package-file-ownership" json:"package-file-ownership" mapstructure:"package-file-ownership"`
	PackageFileOwnershipOverlap                   bool `yaml:"package-file-ownership-overlap" json:"package-file-ownership-overlap" mapstructure:"package-file-ownership-overlap"`
	ExcludeBinaryPackagesWithFileOwnershipOverlap bool `yaml:"exclude-binary-packages-with-file-ownership-overlap" json:"exclude-binary-packages-with-file-ownership-overlap" mapstructure:"exclude-binary-packages-with-file-ownership-overlap"`
}

func DefaultRelationshipsConfig() RelationshipsConfig {
	return RelationshipsConfig{
		PackageFileOwnership:                          true,
		PackageFileOwnershipOverlap:                   true,
		ExcludeBinaryPackagesWithFileOwnershipOverlap: true,
	}
}

func (c RelationshipsConfig) WithPackageFileOwnership(ownership bool) RelationshipsConfig {
	c.PackageFileOwnership = ownership
	return c
}

func (c RelationshipsConfig) WithPackageFileOwnershipOverlap(overlap bool) RelationshipsConfig {
	c.PackageFileOwnershipOverlap = overlap
	return c
}

func (c RelationshipsConfig) WithExcludeBinaryPackagesWithFileOwnershipOverlap(exclude bool) RelationshipsConfig {
	c.ExcludeBinaryPackagesWithFileOwnershipOverlap = exclude
	return c
}
