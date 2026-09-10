package cataloging

import "github.com/anchore/stereoscope/pkg/file"

const (
	DefaultArchiveMaxDepth = 0 // disabled by default for backwards compatibility

	// DefaultArchiveMaxMemoryBytes bounds the archive content held in memory at once.
	//
	// Both bounds are in-use gauges rather than cumulative totals: they measure what the scan is
	// holding right now and fall as each archive is released, so what they cap is a scan's peak.
	// That is what lets them be set well above the largest archive anyone is likely to meet - the
	// number that matters is how much is held at the deepest point of a nesting chain, not the sum
	// of everything the scan ever opened.
	//
	// Set generously on purpose. An archive's entries are held here entry by entry and moved out to
	// the overflow blob the first time this bound says no, so the bound does not decide whether an
	// archive can be cataloged - only whether it costs a write. Making room for the common case is
	// therefore a straight speed win with a bounded cost, and the cost is bounded because what is
	// held is released as soon as the archive is.
	DefaultArchiveMaxMemoryBytes = 2 * file.GB

	// DefaultArchiveMaxDiskBytes bounds the archive content on disk at once.
	//
	// Unlike the memory bound this one is terminal: there is nowhere further to overflow, so an
	// archive whose first byte it refuses is skipped and its packages are absent from the SBOM. It
	// is set high for that reason - it is a backstop against a pathological archive filling the
	// disk, not a working budget - and, being an in-use gauge, it is released along with each
	// archive rather than accumulating over a scan.
	DefaultArchiveMaxDiskBytes = 100 * file.GB
)

type ArchiveSearchConfig struct {
	// IncludeIndexedArchives indicates whether to search within indexed archive files (e.g., .zip).
	IncludeIndexedArchives bool `yaml:"include-indexed-archives" json:"include-indexed-archives" mapstructure:"include-indexed-archives"`

	// IncludeUnindexedArchives indicates whether to search within unindexed archive files (e.g., .tar*).
	IncludeUnindexedArchives bool `yaml:"include-unindexed-archives" json:"include-unindexed-archives" mapstructure:"include-unindexed-archives"`

	// MaxDepth is the maximum depth of recursive archive extraction (0 = disabled, no recursive extraction).
	MaxDepth int `yaml:"max-depth" json:"max-depth" mapstructure:"max-depth"`

	// MaxMemoryBytes is the maximum bytes of archive content held in memory at once. It is an in-use
	// limit: it measures what is held right now and falls when an archive is released, so what it
	// bounds is a scan's peak rather than its cumulative total. Content is held in memory while this
	// limit admits it and overflows to disk when it does not - there is no separate configured size at
	// which overflowing begins. Zero means content is never held in memory and everything overflows; a
	// negative value means memory is not bounded at all.
	MaxMemoryBytes int64 `yaml:"max-memory-bytes" json:"max-memory-bytes" mapstructure:"max-memory-bytes"`

	// MaxDiskBytes is the maximum bytes of archive content on disk at once - content overflowed there
	// plus the entries extracted from it. Also an in-use limit, and terminal: there is nowhere
	// further to overflow, so an archive that would exceed it is skipped. Zero admits no archive
	// content at all, since an archive's entries are stored whatever happened to its own bytes; a
	// negative value means disk is not bounded.
	MaxDiskBytes int64 `yaml:"max-disk-bytes" json:"max-disk-bytes" mapstructure:"max-disk-bytes"`

	// ExclusionPatterns carries the scan's own file exclusion patterns so the code that indexes an
	// archive's contents does not have to interrogate the source for them. This capability has no
	// exclusion setting of its own: it is deliberately not a yaml/json/mapstructure key, so no config
	// file, flag, or environment variable reaches it, and `syft config` never names it.
	//
	// Each boundary that already holds exclusion patterns populates this field from its own: the CLI
	// fills it in cmd/syft/internal/options.Catalog.ToArchiveConfig from the --exclude flag, and
	// syft.CreateSBOM fills it from the source's own published exclusions (source.PathExcluder). A
	// value already present is never overwritten - CreateSBOM consults the source only to fill an
	// empty field - so the boundary closest to the user wins and a library consumer who configures
	// only their source still gets those patterns applied inside archives. Callers building this
	// config directly should leave it alone; the zero value means nothing has populated it yet.
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
// selects them.
//
// This is how the two boundaries that populate the field do it, and it is not a way to configure a
// second exclusion list: the field carries no yaml, json or mapstructure tag, so nothing a user
// writes reaches it. A caller who sets it here is the boundary closest to the user, and
// syft.CreateSBOM will not overwrite a value that is already present.
func (c ArchiveSearchConfig) WithExclusionPatterns(patterns []string) ArchiveSearchConfig {
	c.ExclusionPatterns = patterns
	return c
}
