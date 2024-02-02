package cataloging

type ArchiveSearchConfig struct {
	IncludeIndexedArchives   bool `yaml:"include-indexed-archives" json:"include-indexed-archives" mapstructure:"include-indexed-archives"`
	IncludeUnindexedArchives bool `yaml:"include-unindexed-archives" json:"include-unindexed-archives" mapstructure:"include-unindexed-archives"`
}

func DefaultArchiveSearchConfig() ArchiveSearchConfig {
	return ArchiveSearchConfig{
		IncludeIndexedArchives:   true,
		IncludeUnindexedArchives: false,
	}
}

func (c ArchiveSearchConfig) WithIncludeIndexedArchives(include bool) ArchiveSearchConfig {
	c.IncludeIndexedArchives = include
	return c
}

func (c ArchiveSearchConfig) WithIncludeUnindexedArchives(include bool) ArchiveSearchConfig {
	c.IncludeUnindexedArchives = include
	return c
}
