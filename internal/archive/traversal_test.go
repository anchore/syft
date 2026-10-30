package archive

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

func TestTraversalContextRoundTrip(t *testing.T) {
	assert.Nil(t, TraversalFromContext(context.Background()))

	trav := &Traversal{Location: file.NewLocation("app.war")}
	ctx := WithTraversal(context.Background(), trav)
	require.Same(t, trav, TraversalFromContext(ctx))

	child := &Traversal{Location: locationIn("app.war", "WEB-INF/lib/dep.jar")}
	ctx = WithTraversal(ctx, child)
	require.Same(t, child, TraversalFromContext(ctx))
}

// locationIn is a location as the Resolver returns it: the outermost archive's real path, and the chain
// of entry paths within it.
func locationIn(realPath, archivePath string) file.Location {
	return file.NewLocationFromCoordinates(file.Coordinates{RealPath: realPath, FullPath: realPath + file.ArchivePathSeparator + archivePath})
}

func TestContainerPath(t *testing.T) {
	assert.Equal(t, "", ContainerPath(file.NewCoordinates("/app.war", "")))
	assert.Equal(t, "", ContainerPath(file.Coordinates{RealPath: "/app.war", FullPath: "/app.war"}), "a top-level file whose FullPath is set")
	assert.Equal(t, "", ContainerPath(file.Coordinates{RealPath: "/odd!/name"}), "a separator in a top-level real path is not an archive boundary")
	assert.Equal(t, "", ContainerPath(file.Coordinates{RealPath: "/odd!/name", FullPath: "/odd!/name"}), "nor when FullPath is set")
	assert.Equal(t, "/odd!/name.zip", ContainerPath(locationIn("/odd!/name.zip", "a.txt").Coordinates))
	assert.Equal(t, "/odd!/name.zip!/b.jar", ContainerPath(locationIn("/odd!/name.zip", "b.jar!/a.txt").Coordinates))
	assert.Equal(t, "/app.war", ContainerPath(locationIn("/app.war", "WEB-INF/lib/dep.jar").Coordinates))
	assert.Equal(t, "/app.war!/WEB-INF/lib/dep.jar",
		ContainerPath(locationIn("/app.war", "WEB-INF/lib/dep.jar!/META-INF/MANIFEST.MF").Coordinates))
}

func TestVirtualPath(t *testing.T) {
	tests := []struct {
		name     string
		location file.Location
		expected string
	}{
		{
			name:     "outside an archive returns the path unchanged",
			location: file.NewLocation("/WEB-INF/lib/dep.jar"),
			expected: "/WEB-INF/lib/dep.jar",
		},
		{
			name:     "outside an archive preserves a relative path",
			location: file.NewLocation("some/dir/example.jar"),
			expected: "some/dir/example.jar",
		},
		{
			name:     "outside an archive with FullPath set returns the path unchanged",
			location: file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/odd!/name.jar", FullPath: "/odd!/name.jar"}),
			expected: "/odd!/name.jar",
		},
		{
			name:     "single level trims leading slash",
			location: locationIn("app.war", "/WEB-INF/lib/dep.jar"),
			expected: "app.war:WEB-INF/lib/dep.jar",
		},
		{
			name:     "single level with slash-less entry",
			location: locationIn("app.war", "WEB-INF/lib/dep.jar"),
			expected: "app.war:WEB-INF/lib/dep.jar",
		},
		{
			name:     "multi-level chain",
			location: locationIn("app.war", "WEB-INF/lib/dep.jar!/inner/most.jar"),
			expected: "app.war:WEB-INF/lib/dep.jar:inner/most.jar",
		},
		{
			// a colon in the entry name must not be mistaken for a chain delimiter
			name:     "colon in entry path is escaped",
			location: locationIn("app.war", "WEB-INF/lib/dep:special.jar"),
			expected: "app.war:WEB-INF/lib/dep%3Aspecial.jar",
		},
		{
			name:     "every colon in the entry path is escaped",
			location: locationIn("app.war", "lib/a:b:c.jar"),
			expected: "app.war:lib/a%3Ab%3Ac.jar",
		},
		{
			// or the literal text %3A would collide with an escaped colon
			name:     "the escape character is itself escaped",
			location: locationIn("outer.zip", "a%3Ab.jar"),
			expected: "outer.zip:a%253Ab.jar",
		},
		{
			name:     "access path is preferred over real path",
			location: file.NewVirtualLocation("/real/dep.jar", "/link/dep.jar"),
			expected: "/link/dep.jar",
		},
		{
			name: "access path within an archive replaces the last entry",
			location: file.NewVirtualLocationFromCoordinates(
				file.Coordinates{RealPath: "app.war", FullPath: "app.war!/WEB-INF/lib/real.jar"}, "app.war!/WEB-INF/lib/link.jar"),
			expected: "app.war:WEB-INF/lib/link.jar",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, VirtualPath(tt.location))
		})
	}
}
