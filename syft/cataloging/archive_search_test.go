package cataloging

import (
	"reflect"
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

func TestArchiveSearchConfig_namesNoSeparateOverflowSize(t *testing.T) {
	// two things are asserted by one list. The boundary between memory and disk is decided by the
	// memory limit alone, so the surface must never grow a field naming a separate size at which
	// content overflows. And nested archive cataloging honors the scan's own exclusion patterns, so the
	// surface must name no exclusion setting of its own - an archive extension list here would be a
	// second mechanism for a question the scan already answers.
	// ExclusionPatterns is on the struct but is NOT config surface: it is derived, written only by
	// CreateSBOM from what the source published, and reachable from no file, flag or variable. So it
	// is listed here and separately asserted to carry no tags - which is what keeps this test able to
	// catch a SETTABLE addition rather than merely any addition.
	var settable, derived []string
	typ := reflect.TypeOf(ArchiveSearchConfig{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Tag.Get("yaml") == "-" && f.Tag.Get("json") == "-" && f.Tag.Get("mapstructure") == "-" {
			derived = append(derived, f.Name)
			continue
		}
		settable = append(settable, f.Name)
	}
	assert.Equal(t, []string{
		"IncludeIndexedArchives",
		"IncludeUnindexedArchives",
		"MaxDepth",
		"MaxMemoryBytes",
		"MaxDiskBytes",
	}, settable, "a new SETTABLE field means a new way to configure this capability")
	assert.Equal(t, []string{"ExclusionPatterns"}, derived,
		"a derived field must stay untagged, or it becomes config surface without anyone deciding it should")
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
