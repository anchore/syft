package cataloging

type RelationshipsConfig struct {
	FileOwnership                                 bool `yaml:"file-ownership" json:"file-ownership" mapstructure:"file-ownership"`
	FileOwnershipOverlap                          bool `yaml:"file-ownership-overlap" json:"file-ownership-overlap" mapstructure:"file-ownership-overlap"`
	ExcludeBinaryPackagesWithFileOwnershipOverlap bool `yaml:"exclude-binary-packages-with-file-ownership-overlap" json:"exclude-binary-packages-with-file-ownership-overlap" mapstructure:"exclude-binary-packages-with-file-ownership-overlap"`
}

func DefaultRelationshipsConfig() RelationshipsConfig {
	return RelationshipsConfig{
		FileOwnership:        true,
		FileOwnershipOverlap: true,
		ExcludeBinaryPackagesWithFileOwnershipOverlap: true,
	}
}

func (c RelationshipsConfig) WithFileOwnership(ownership bool) RelationshipsConfig {
	c.FileOwnership = ownership
	return c
}

func (c RelationshipsConfig) WithFileOwnershipOverlap(overlap bool) RelationshipsConfig {
	c.FileOwnershipOverlap = overlap
	return c
}

func (c RelationshipsConfig) WithExcludeBinaryPackagesWithFileOwnershipOverlap(exclude bool) RelationshipsConfig {
	c.ExcludeBinaryPackagesWithFileOwnershipOverlap = exclude
	return c
}
