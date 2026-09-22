package cataloging

import "github.com/anchore/stereoscope/pkg/file"

const (
	// DefaultArchiveMaxDepth is 0: nested archives are not cataloged unless asked for.
	DefaultArchiveMaxDepth = 0

	// DefaultArchiveMaxMemoryBytes bounds the archive content held in memory at once. It decides only
	// whether an archive costs a write: content that does not fit goes to disk and is cataloged anyway.
	DefaultArchiveMaxMemoryBytes = 2 * file.GB

	// DefaultArchiveMaxDiskBytes bounds the archive content on disk at once. Content that does not fit
	// has nowhere to go, so the archive holding it is skipped or truncated. Set high as a backstop
	// against a pathological archive filling the disk.
	DefaultArchiveMaxDiskBytes = 100 * file.GB
)

type ArchiveSearchConfig struct {
	// IncludeIndexedArchives indicates whether to search within indexed archive files (e.g., .zip).
	IncludeIndexedArchives bool `yaml:"include-indexed-archives" json:"include-indexed-archives" mapstructure:"include-indexed-archives"`

	// IncludeUnindexedArchives indicates whether to search within unindexed archive files (e.g., .tar*).
	IncludeUnindexedArchives bool `yaml:"include-unindexed-archives" json:"include-unindexed-archives" mapstructure:"include-unindexed-archives"`

	// MaxDepth is how many levels of nested archives to catalog: 0 disables it, negative is unbounded.
	MaxDepth int `yaml:"max-depth" json:"max-depth" mapstructure:"max-depth"`

	// MaxMemoryBytes bounds the archive content held in memory at once; content that does not fit is
	// written to disk. Zero writes everything to disk, negative is unbounded.
	MaxMemoryBytes int64 `yaml:"max-memory-bytes" json:"max-memory-bytes" mapstructure:"max-memory-bytes"`

	// MaxDiskBytes bounds the archive content written to disk at once; an archive whose content does
	// not fit is skipped or truncated. Zero writes nothing to disk, negative is unbounded.
	MaxDiskBytes int64 `yaml:"max-disk-bytes" json:"max-disk-bytes" mapstructure:"max-disk-bytes"`
}

func DefaultArchiveSearchConfig() ArchiveSearchConfig {
	return ArchiveSearchConfig{
		IncludeIndexedArchives:   true,
		IncludeUnindexedArchives: false,
		MaxDepth:                 DefaultArchiveMaxDepth,
		MaxMemoryBytes:           DefaultArchiveMaxMemoryBytes,
		MaxDiskBytes:             DefaultArchiveMaxDiskBytes,
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

func (c ArchiveSearchConfig) WithMaxMemoryBytes(size int64) ArchiveSearchConfig {
	c.MaxMemoryBytes = size
	return c
}

func (c ArchiveSearchConfig) WithMaxDiskBytes(size int64) ArchiveSearchConfig {
	c.MaxDiskBytes = size
	return c
}
