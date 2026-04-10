package cataloging

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultArchiveSearchConfig(t *testing.T) {
	cfg := DefaultArchiveSearchConfig()

	assert.True(t, cfg.IncludeIndexedArchives)
	assert.False(t, cfg.IncludeUnindexedArchives)
	assert.Equal(t, DefaultArchiveMaxDepth, cfg.MaxDepth)
	assert.Equal(t, int64(DefaultArchiveMaxExtractionSizeBytes), cfg.MaxExtractionSizeBytes)
	assert.Equal(t, DefaultArchiveMaxFileCount, cfg.MaxFileCount)
	assert.Equal(t, int64(DefaultArchiveMaxTotalExtractionBytes), cfg.MaxTotalExtractionBytes)
	assert.Nil(t, cfg.ExcludeExtensions)
}

func TestArchiveSearchConfig_WithMethods(t *testing.T) {
	cfg := DefaultArchiveSearchConfig()

	cfg = cfg.WithMaxDepth(5)
	assert.Equal(t, 5, cfg.MaxDepth)

	cfg = cfg.WithMaxExtractionSizeBytes(1024)
	assert.Equal(t, int64(1024), cfg.MaxExtractionSizeBytes)

	cfg = cfg.WithMaxFileCount(100)
	assert.Equal(t, 100, cfg.MaxFileCount)

	cfg = cfg.WithMaxTotalExtractionBytes(2048)
	assert.Equal(t, int64(2048), cfg.MaxTotalExtractionBytes)

	cfg = cfg.WithExcludeExtensions([]string{".rpm", ".deb"})
	assert.Equal(t, []string{".rpm", ".deb"}, cfg.ExcludeExtensions)

	cfg = cfg.WithIncludeIndexedArchives(false)
	assert.False(t, cfg.IncludeIndexedArchives)

	cfg = cfg.WithIncludeUnindexedArchives(true)
	assert.True(t, cfg.IncludeUnindexedArchives)
}
