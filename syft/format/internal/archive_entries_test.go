package internal

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
)

func TestArchiveEntries(t *testing.T) {
	top := file.NewCoordinates("/etc/passwd", "layer")
	odd := file.NewCoordinates("/odd!/name", "layer") // a separator in a real path is not an archive boundary
	war := file.NewCoordinates("/app.war", "layer")
	jar := file.Coordinates{RealPath: "/app.war", FileSystemID: "layer", FullPath: "/app.war!/WEB-INF/lib/a.jar"}
	manifest := file.Coordinates{RealPath: "/app.war", FileSystemID: "layer", FullPath: "/app.war!/WEB-INF/lib/a.jar!/META-INF/MANIFEST.MF"}
	index := file.Coordinates{RealPath: "/app.war", FileSystemID: "layer", FullPath: "/app.war!/index.html"}

	byPath := func(a, b file.Coordinates) int { return strings.Compare(a.FullNestedPath(), b.FullNestedPath()) }
	root := file.Coordinates{} // a directory scan's root
	gotTop, gotEntries := ArchiveEntries([]file.Coordinates{top, root, odd, manifest, index}, byPath)

	assert.Equal(t, []file.Coordinates{root, war, top, odd}, gotTop)
	assert.Equal(t, map[file.Coordinates][]file.Coordinates{
		war: {jar, index},
		jar: {manifest},
	}, gotEntries)
}
