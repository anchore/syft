package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cataloging"
)

func Test_packageConfigDefaultsMatchArchiveSearchConfig(t *testing.T) {
	want := cataloging.DefaultArchiveSearchConfig()
	got := defaultPackageConfig()

	assert.Equal(t, want.MaxDepth, got.NestedArchiveMaxDepth)
	assert.Equal(t, want.MaxMemoryBytes, got.NestedArchiveMaxMemoryBytes)
	assert.Equal(t, want.MaxDiskBytes, got.NestedArchiveMaxDiskBytes)

	require.Zero(t, got.NestedArchiveMaxDepth, "nested archive cataloging must be off by default")
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
		// a key that parses but is not carried into the archive config is invisible in a config
		// dump, so assert each one arrives
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
}
