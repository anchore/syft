package cataloging

import "github.com/anchore/stereoscope/pkg/file"

const (
	DefaultArchiveMaxDepth = 0 // off by default, so old scans work the same way

	// DefaultArchiveMaxMemoryBytes bounds the archive content held in memory at once. Both bounds are
	// in-use gauges: each measures what is held at a moment and falls as the scan releases an archive,
	// so the peak they cap is the deepest point of a nesting chain, not the sum of everything opened.
	// Set generously: it decides only whether an archive costs a write. Once refused, an archive's
	// entries spill to the overflow blob and syft catalogs it either way.
	DefaultArchiveMaxMemoryBytes = 2 * file.GB

	// DefaultArchiveMaxDiskBytes bounds the archive content on disk at once. This bound is terminal:
	// spilled content has nowhere further to go, so syft skips an archive whose first byte it refuses,
	// leaving that archive's packages out of the SBOM. Set high, as a backstop against a pathological
	// archive filling the disk; it is a poor working budget.
	DefaultArchiveMaxDiskBytes = 100 * file.GB
)

type ArchiveSearchConfig struct {
	// IncludeIndexedArchives indicates whether to search within indexed archive files (e.g., .zip).
	IncludeIndexedArchives bool `yaml:"include-indexed-archives" json:"include-indexed-archives" mapstructure:"include-indexed-archives"`

	// IncludeUnindexedArchives indicates whether to search within unindexed archive files (e.g., .tar*).
	IncludeUnindexedArchives bool `yaml:"include-unindexed-archives" json:"include-unindexed-archives" mapstructure:"include-unindexed-archives"`

	// MaxDepth is the maximum depth of recursive archive extraction (0 disables it).
	MaxDepth int `yaml:"max-depth" json:"max-depth" mapstructure:"max-depth"`

	// MaxMemoryBytes is the max archive content held in memory at once, an in-use gauge that falls as
	// the scan releases an archive, so it bounds the peak. Content spills to disk once this stops
	// admitting it, the only spill threshold. Zero spills everything; negative is unbounded.
	MaxMemoryBytes int64 `yaml:"max-memory-bytes" json:"max-memory-bytes" mapstructure:"max-memory-bytes"`

	// MaxDiskBytes is the max archive content on disk at once: spilled content plus the entries
	// extracted from it. Also an in-use gauge, and terminal, since spilled content has nowhere further
	// to go; syft skips an archive that would exceed it. Zero keeps every archive out of the work
	// directory; negative is unbounded.
	MaxDiskBytes int64 `yaml:"max-disk-bytes" json:"max-disk-bytes" mapstructure:"max-disk-bytes"`

	// ExclusionPatterns carries the scan's file exclusion patterns so the code indexing an archive's
	// contents need not interrogate the source for them. It has no config key, so no config file, flag
	// or environment variable reaches it and `syft config` never names it.
	//
	// Each boundary holding exclusion patterns populates it: the CLI from `--exclude`
	// (options.Catalog.ToArchiveConfig), and syft.CreateSBOM from the source's published exclusions
	// (source.PathExcluder). CreateSBOM fills only an empty field, so the boundary closest to the user
	// wins, and a consumer who configures only their source still gets those patterns applied inside
	// archives. Callers building this config directly should leave it alone.
	ExclusionPatterns []string `yaml:"-" json:"-" mapstructure:"-"`
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

// WithExclusionPatterns sets the scan's exclusion patterns for the code that indexes an archive's
// contents. Only patterns whose shape reaches inside an archive belong here; ArchiveExclusionPatterns
// selects them. syft.CreateSBOM will not overwrite a value already set here.
func (c ArchiveSearchConfig) WithExclusionPatterns(patterns []string) ArchiveSearchConfig {
	c.ExclusionPatterns = patterns
	return c
}
