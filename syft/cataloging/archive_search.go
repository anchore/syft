package cataloging

const (
	DefaultArchiveMaxDepth                = 0 // disabled by default for backwards compatibility
	DefaultArchiveMaxExtractionSizeBytes  = 500 * 1024 * 1024 // 500 MB per archive
	DefaultArchiveMaxFileCount            = 10000
	DefaultArchiveMaxTotalExtractionBytes = 2 * 1024 * 1024 * 1024 // 2 GB total
)

type ArchiveSearchConfig struct {
	// IncludeIndexedArchives indicates whether to search within indexed archive files (e.g., .zip).
	IncludeIndexedArchives bool `yaml:"include-indexed-archives" json:"include-indexed-archives" mapstructure:"include-indexed-archives"`

	// IncludeUnindexedArchives indicates whether to search within unindexed archive files (e.g., .tar*).
	IncludeUnindexedArchives bool `yaml:"include-unindexed-archives" json:"include-unindexed-archives" mapstructure:"include-unindexed-archives"`

	// MaxDepth is the maximum depth of recursive archive extraction (0 = disabled, no recursive extraction).
	MaxDepth int `yaml:"max-depth" json:"max-depth" mapstructure:"max-depth"`

	// MaxExtractionSizeBytes is the maximum total bytes to extract from a single archive before stopping.
	MaxExtractionSizeBytes int64 `yaml:"max-extraction-size-bytes" json:"max-extraction-size-bytes" mapstructure:"max-extraction-size-bytes"`

	// MaxFileCount is the maximum number of files to extract from a single archive before stopping.
	MaxFileCount int `yaml:"max-file-count" json:"max-file-count" mapstructure:"max-file-count"`

	// MaxTotalExtractionBytes is the maximum total bytes to extract across all archives before stopping.
	MaxTotalExtractionBytes int64 `yaml:"max-total-extraction-bytes" json:"max-total-extraction-bytes" mapstructure:"max-total-extraction-bytes"`

	// ExcludeExtensions is a list of archive extensions to skip during recursive extraction (e.g., [".rpm"]).
	ExcludeExtensions []string `yaml:"exclude-extensions" json:"exclude-extensions" mapstructure:"exclude-extensions"`
}

func DefaultArchiveSearchConfig() ArchiveSearchConfig {
	return ArchiveSearchConfig{
		IncludeIndexedArchives:   true,
		IncludeUnindexedArchives: false,
		MaxDepth:                 DefaultArchiveMaxDepth,
		MaxExtractionSizeBytes:   DefaultArchiveMaxExtractionSizeBytes,
		MaxFileCount:             DefaultArchiveMaxFileCount,
		MaxTotalExtractionBytes:  DefaultArchiveMaxTotalExtractionBytes,
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

func (c ArchiveSearchConfig) WithMaxDepth(depth int) ArchiveSearchConfig {
	c.MaxDepth = depth
	return c
}

func (c ArchiveSearchConfig) WithMaxExtractionSizeBytes(size int64) ArchiveSearchConfig {
	c.MaxExtractionSizeBytes = size
	return c
}

func (c ArchiveSearchConfig) WithMaxFileCount(count int) ArchiveSearchConfig {
	c.MaxFileCount = count
	return c
}

func (c ArchiveSearchConfig) WithMaxTotalExtractionBytes(size int64) ArchiveSearchConfig {
	c.MaxTotalExtractionBytes = size
	return c
}

func (c ArchiveSearchConfig) WithExcludeExtensions(extensions []string) ArchiveSearchConfig {
	c.ExcludeExtensions = extensions
	return c
}
