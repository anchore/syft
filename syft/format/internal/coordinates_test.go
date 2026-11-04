package internal

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/archive"
	"github.com/anchore/syft/syft/file"
)

func TestNestedCoordinates(t *testing.T) {
	war := file.NewCoordinates("/app.war", "layer")

	got, ok := NestedCoordinates(war, "/WEB-INF/lib/a.jar")
	require.True(t, ok)
	assert.Equal(t, file.Coordinates{RealPath: "/app.war", FileSystemID: "layer", FullPath: "/app.war!/WEB-INF/lib/a.jar"}, got)

	for _, name := range []string{"", "/", "a.jar!/BOOT-INF/lib/b.jar", "a\nb", strings.Repeat("a", 4097)} {
		_, ok := NestedCoordinates(war, name)
		assert.False(t, ok, "%q", name)
	}

	// nesting stops as deep as a scan goes
	c := war
	for range archive.MaxDepth {
		c, ok = NestedCoordinates(c, "a.jar")
		require.True(t, ok)
	}
	_, ok = NestedCoordinates(c, "a.jar")
	assert.False(t, ok)

	// so does a chain longer than a path, however it gets there: a long container name shared by many entries
	// would otherwise cost memory quadratic in the document
	long := file.NewCoordinates("/"+strings.Repeat("a", archive.MaxPathBytes), "layer")
	_, ok = NestedCoordinates(long, "a.jar")
	assert.False(t, ok)
	c = war
	for range 3 {
		c, ok = NestedCoordinates(c, strings.Repeat("a", 2000))
	}
	assert.False(t, ok)
}
