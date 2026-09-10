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

	trav := &Traversal{
		Location:     file.NewLocation("app.war"),
		VirtualPath:  "app.war",
		FileSystemID: "",
		Depth:        1,
	}
	ctx := WithTraversal(context.Background(), trav)
	require.Same(t, trav, TraversalFromContext(ctx))

	child := &Traversal{
		Location:     file.NewLocation("/WEB-INF/lib/dep.jar"),
		VirtualPath:  trav.VirtualPathOf("/WEB-INF/lib/dep.jar"),
		FileSystemID: "",
		Depth:        2,
		Parent:       trav,
	}
	ctx = WithTraversal(ctx, child)
	require.Same(t, child, TraversalFromContext(ctx))
	assert.Same(t, trav, TraversalFromContext(ctx).Parent)
}

func TestTraversal_VirtualPathOf(t *testing.T) {
	tests := []struct {
		name      string
		traversal *Traversal
		entryPath string
		expected  string
	}{
		{
			name:      "nil traversal returns entry path unchanged",
			traversal: nil,
			entryPath: "/WEB-INF/lib/dep.jar",
			expected:  "/WEB-INF/lib/dep.jar",
		},
		{
			name:      "nil traversal preserves relative path",
			traversal: nil,
			entryPath: "some/dir/example.jar",
			expected:  "some/dir/example.jar",
		},
		{
			name:      "single level trims leading slash",
			traversal: &Traversal{VirtualPath: "app.war"},
			entryPath: "/WEB-INF/lib/dep.jar",
			expected:  "app.war:WEB-INF/lib/dep.jar",
		},
		{
			name:      "single level with slash-less entry",
			traversal: &Traversal{VirtualPath: "app.war"},
			entryPath: "WEB-INF/lib/dep.jar",
			expected:  "app.war:WEB-INF/lib/dep.jar",
		},
		{
			name:      "multi-level chain",
			traversal: &Traversal{VirtualPath: "app.war:WEB-INF/lib/dep.jar"},
			entryPath: "/inner/most.jar",
			expected:  "app.war:WEB-INF/lib/dep.jar:inner/most.jar",
		},
		{
			// a colon in the entry name itself must not be mistaken for a chain delimiter -
			// see decisions.md#colon-in-an-entry-path-is-escaped
			name:      "colon in entry path is escaped",
			traversal: &Traversal{VirtualPath: "app.war"},
			entryPath: "WEB-INF/lib/dep:special.jar",
			expected:  "app.war:WEB-INF/lib/dep%3Aspecial.jar",
		},
		{
			name:      "every colon in the entry path is escaped",
			traversal: &Traversal{VirtualPath: "app.war"},
			entryPath: "lib/a:b:c.jar",
			expected:  "app.war:lib/a%3Ab%3Ac.jar",
		},
		{
			// a traversal carrying no virtual path (as distinct from a nil traversal) still
			// yields the entry path alone, never a bare leading colon
			name:      "empty virtual path yields the entry path alone, no leading colon",
			traversal: &Traversal{VirtualPath: ""},
			entryPath: "WEB-INF/lib/dep.jar",
			expected:  "WEB-INF/lib/dep.jar",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.traversal.VirtualPathOf(tt.entryPath))
		})
	}
}

// TestTraversal_VirtualPathOf_noColonIsByteIdenticalToPreEscaping is the assertion that carries
// the compatibility guarantee behind java-virtual-path-identity-preserved
// (decisions.md#colon-in-an-entry-path-is-escaped): escaping a colon in an entry path must not
// alter the result for any entry path that does not contain one. Every case below has no colon,
// and every expected value is exactly what VirtualPathOf produced before escaping existed - do
// not "fix" a failure here by updating the expected string, since that is precisely the
// regression this test exists to catch.
func TestTraversal_VirtualPathOf_noColonIsByteIdenticalToPreEscaping(t *testing.T) {
	tests := []struct {
		name      string
		traversal *Traversal
		entryPath string
		expected  string
	}{
		{
			name:      "nil traversal, absolute entry path",
			traversal: nil,
			entryPath: "/WEB-INF/lib/dep.jar",
			expected:  "/WEB-INF/lib/dep.jar",
		},
		{
			name:      "nil traversal, relative entry path",
			traversal: nil,
			entryPath: "some/dir/example.jar",
			expected:  "some/dir/example.jar",
		},
		{
			name:      "single level, leading slash trimmed",
			traversal: &Traversal{VirtualPath: "app.war"},
			entryPath: "/WEB-INF/lib/dep.jar",
			expected:  "app.war:WEB-INF/lib/dep.jar",
		},
		{
			name:      "single level, no leading slash",
			traversal: &Traversal{VirtualPath: "app.war"},
			entryPath: "WEB-INF/lib/dep.jar",
			expected:  "app.war:WEB-INF/lib/dep.jar",
		},
		{
			name:      "multi-level chain",
			traversal: &Traversal{VirtualPath: "app.war:WEB-INF/lib/dep.jar"},
			entryPath: "/inner/most.jar",
			expected:  "app.war:WEB-INF/lib/dep.jar:inner/most.jar",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.traversal.VirtualPathOf(tt.entryPath))
		})
	}
}

// TestTraversal_VirtualPathOf_escapingComposesAcrossNestingLevels asserts that escaping is
// applied at every level of a chain, not only the first: a colon in an entry name at a deeper
// nesting level is just as ambiguous as one at the outermost level, so it gets the same
// treatment. After composing, splitting the result on ':' must yield exactly one segment per
// real archive boundary - none of the escaped colons survive as a literal ':' byte, so they
// cannot be mistaken for delimiters by a naive splitter.
func TestTraversal_VirtualPathOf_theEscapeCharacterIsNotItselfEscaped(t *testing.T) {
	// a known and accepted limit, not a defect: an entry path holding the literal text %3A is
	// indistinguishable from one holding a colon. Escaping % as %25 would close it and is
	// deliberately not done, because % is far more common in real paths than : and closing this
	// would move a large number of well-defined identities to resolve a collision between two
	// inputs both already assumed absent. Asserted so the limit is a decision on the record
	// rather than something a later reader discovers and "fixes".
	t.Parallel()

	outer := &Traversal{VirtualPath: "outer.zip"}

	fromColon := outer.VirtualPathOf("a:b.jar")
	fromLiteral := outer.VirtualPathOf("a%3Ab.jar")

	assert.Equal(t, "outer.zip:a%3Ab.jar", fromColon)
	assert.Equal(t, "outer.zip:a%3Ab.jar", fromLiteral)
	assert.Equal(t, fromColon, fromLiteral,
		"the collision is accepted; if this ever differs, the escape character started being escaped")
}

func TestTraversal_VirtualPathOf_escapingComposesAcrossNestingLevels(t *testing.T) {
	level1 := &Traversal{VirtualPath: "outer.zip"}
	level2VirtualPath := level1.VirtualPathOf("lib/mid:dle.war")
	require.Equal(t, "outer.zip:lib/mid%3Adle.war", level2VirtualPath)

	level2 := &Traversal{VirtualPath: level2VirtualPath}
	final := level2.VirtualPathOf("WEB-INF/lib/inn:er.jar")
	require.Equal(t, "outer.zip:lib/mid%3Adle.war:WEB-INF/lib/inn%3Aer.jar", final)

	assert.Equal(t,
		[]string{"outer.zip", "lib/mid%3Adle.war", "WEB-INF/lib/inn%3Aer.jar"},
		strings.Split(final, ":"),
		"splitting on ':' must recover exactly the three real archive boundaries",
	)
}
