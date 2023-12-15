package options

type relationshipsConfig struct {
	FileOwnership        bool `mapstructure:"file-ownership" json:"file-ownership" yaml:"file-ownership"`
	FileOwnershipOverlap bool `mapstructure:"file-ownership-overlap" json:"file-ownership-overlap" yaml:"file-ownership-overlap"`
}

func defaultRelationships() relationshipsConfig {
	return relationshipsConfig{
		FileOwnership:        true,
		FileOwnershipOverlap: true,
	}
}
