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
	assert.Equal(t, int64(DefaultArchiveMaxMemoryBytes), cfg.MaxMemoryBytes)
	assert.Equal(t, int64(DefaultArchiveMaxDiskBytes), cfg.MaxDiskBytes)
}

func TestArchiveSearchConfig_WithMethods(t *testing.T) {
	cfg := DefaultArchiveSearchConfig()

	cfg = cfg.WithMaxDepth(5)
	assert.Equal(t, 5, cfg.MaxDepth)

	cfg = cfg.WithMaxMemoryBytes(1024)
	assert.Equal(t, int64(1024), cfg.MaxMemoryBytes)

	cfg = cfg.WithMaxDiskBytes(2048)
	assert.Equal(t, int64(2048), cfg.MaxDiskBytes)

	cfg = cfg.WithIncludeIndexedArchives(false)
	assert.False(t, cfg.IncludeIndexedArchives)

	cfg = cfg.WithIncludeUnindexedArchives(true)
	assert.True(t, cfg.IncludeUnindexedArchives)
}
