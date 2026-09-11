package options

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cataloging"
)

func Test_packageConfigDefaultsMatchArchiveSearchConfig(t *testing.T) {
	// the nested-archive settings must default to the values in syft/cataloging rather than
	// restating them, so a config round trip with nothing set is a no-op
	want := cataloging.DefaultArchiveSearchConfig()
	got := defaultPackageConfig()

	assert.Equal(t, want.MaxDepth, got.NestedArchiveMaxDepth)
	assert.Equal(t, want.MaxMemoryBytes, got.NestedArchiveMaxMemoryBytes)
	assert.Equal(t, want.MaxDiskBytes, got.NestedArchiveMaxDiskBytes)

	require.Zero(t, got.NestedArchiveMaxDepth, "nested archive cataloging must be off by default")
}

func Test_packageConfigNamesNoArchiveExclusionSetting(t *testing.T) {
	// nested archive cataloging honors the scan's own --exclude patterns, so the application config
	// must name no archive-specific exclusion key. Asserted over the yaml tags rather than over the
	// Go field names, because the key is what a user writes and what a config dump shows.
	var keys []string
	typ := reflect.TypeOf(packageConfig{})
	for i := 0; i < typ.NumField(); i++ {
		keys = append(keys, typ.Field(i).Tag.Get("yaml"))
	}

	assert.Equal(t, []string{
		"search-unindexed-archives",
		"search-indexed-archives",
		"exclude-binary-overlap-by-ownership",
		"nested-archive-max-depth",
		"nested-archive-max-memory-bytes",
		"nested-archive-max-disk-bytes",
	}, keys)
}

func Test_ToArchiveConfig(t *testing.T) {
	defaults := cataloging.DefaultArchiveSearchConfig()

	t.Run("defaults round trip unchanged", func(t *testing.T) {
		cfg := Catalog{Package: defaultPackageConfig()}
		got := cfg.ToArchiveConfig()

		assert.Equal(t, defaults.MaxDepth, got.MaxDepth)
		assert.Equal(t, defaults.MaxMemoryBytes, got.MaxMemoryBytes)
		assert.Equal(t, defaults.MaxDiskBytes, got.MaxDiskBytes)
	})

	t.Run("every setting is threaded through", func(t *testing.T) {
		// a key that parses but is not carried into the archive config is invisible in a
		// config dump, so assert each one arrives
		cfg := Catalog{Package: packageConfig{
			NestedArchiveMaxDepth:       3,
			NestedArchiveMaxMemoryBytes: 111,
			NestedArchiveMaxDiskBytes:   3333,
			SearchIndexedArchives:       true,
			SearchUnindexedArchives:     true,
		}}
		got := cfg.ToArchiveConfig()

		assert.Equal(t, 3, got.MaxDepth)
		assert.Equal(t, int64(111), got.MaxMemoryBytes)
		assert.Equal(t, int64(3333), got.MaxDiskBytes)
		assert.True(t, got.IncludeIndexedArchives)
		assert.True(t, got.IncludeUnindexedArchives)
	})

	t.Run("--exclude patterns arrive already filtered to the in-scope subset, with no source involved", func(t *testing.T) {
		// every-boundary-populates-the-patterns: the CLI is one of the two boundaries that fills
		// ExclusionPatterns, from Catalog.Exclusions, applying the same shape rule the library
		// entry point applies to what the source publishes - only a pattern that reaches inside an
		// archive (any-depth, "**/") is in scope. A root-anchored or one-level pattern is not, and
		// no source is consulted to produce this: Catalog carries no source at all.
		cfg := Catalog{Exclusions: []string{"./root-anchored", "**/*.rpm", "*/one-level", "**/vendor"}}
		assert.Equal(t, []string{"**/*.rpm", "**/vendor"}, cfg.ToArchiveConfig().ExclusionPatterns)
	})

	t.Run("no --exclude patterns leaves the field empty", func(t *testing.T) {
		cfg := Catalog{}
		assert.Empty(t, cfg.ToArchiveConfig().ExclusionPatterns)
	})
}
