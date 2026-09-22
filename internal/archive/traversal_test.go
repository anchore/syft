package archive

import (
	"context"
	"strings"
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

	child := &Traversal{Location: locationIn("app.war", "/WEB-INF/lib/dep.jar")}
	ctx = WithTraversal(ctx, child)
	require.Same(t, child, TraversalFromContext(ctx))
}

// locationIn is a location as the Index returns it: an entry path stamped with the containing chain.
func locationIn(archivePath, entryPath string) file.Location {
	loc := file.NewLocation(entryPath)
	loc.ArchivePath = archivePath
	return loc
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
			location: locationIn("app.war:WEB-INF/lib/dep.jar", "/inner/most.jar"),
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
			name:     "access path is preferred over real path",
			location: file.NewVirtualLocation("/real/dep.jar", "/link/dep.jar"),
			expected: "/link/dep.jar",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, VirtualPath(tt.location))
		})
	}
}

func TestVirtualPath_theEscapeCharacterIsNotItselfEscaped(t *testing.T) {
	// an accepted limit: an entry path holding the literal text %3A is indistinguishable from one holding
	// a colon. Escaping % too would move many more real identities than it protects.
	fromColon := VirtualPath(locationIn("outer.zip", "a:b.jar"))
	fromLiteral := VirtualPath(locationIn("outer.zip", "a%3Ab.jar"))

	assert.Equal(t, "outer.zip:a%3Ab.jar", fromColon)
	assert.Equal(t, fromColon, fromLiteral)
}

func TestVirtualPath_escapingComposesAcrossNestingLevels(t *testing.T) {
	level2 := VirtualPath(locationIn("outer.zip", "lib/mid:dle.war"))
	require.Equal(t, "outer.zip:lib/mid%3Adle.war", level2)

	final := VirtualPath(locationIn(level2, "WEB-INF/lib/inn:er.jar"))
	require.Equal(t, "outer.zip:lib/mid%3Adle.war:WEB-INF/lib/inn%3Aer.jar", final)

	assert.Equal(t,
		[]string{"outer.zip", "lib/mid%3Adle.war", "WEB-INF/lib/inn%3Aer.jar"},
		strings.Split(final, ":"),
		"splitting on ':' must recover exactly the three real archive boundaries",
	)
}
