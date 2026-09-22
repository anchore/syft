package archive

import (
	"context"
	"strings"

	"github.com/anchore/syft/syft/file"
)

// Traversal describes the archive whose contents a cataloger is running against. The archive
// cataloger task puts one on the context before running catalogers inside an archive, so a cataloger
// such as java can describe the archive it is inside without owning the recursion.
type Traversal struct {
	// Location is the archive file's location within its parent filesystem. Its ArchivePath names the
	// archives above it, so VirtualPath(Location) is the full chain from the scan root.
	Location file.Location

	// Digests are of the archive file itself, taken during extraction; a cataloger running inside the
	// archive cannot compute them since the archive is not inside itself.
	Digests []file.Digest
}

// VirtualPath returns the colon-delimited chain of archives from the scan root to loc, ending in loc
// itself: "app.war:WEB-INF/lib/dep.jar". Outside any archive it is the location's path unchanged. A
// colon in an entry name is escaped so splitting on ':' recovers the archive boundaries; the leading
// slash is dropped to match the java cataloger, which joins slash-less zip entry names onto the
// containing archive's path.
func VirtualPath(loc file.Location) string {
	if loc.ArchivePath == "" {
		return loc.Path()
	}
	entryPath := strings.ReplaceAll(loc.Path(), ":", "%3A")
	return loc.ArchivePath + ":" + strings.TrimPrefix(entryPath, "/")
}

type traversalCtxKey struct{}

func WithTraversal(ctx context.Context, t *Traversal) context.Context {
	return context.WithValue(ctx, traversalCtxKey{}, t)
}

// TraversalFromContext returns the archive traversal on the context, or nil outside an archive.
func TraversalFromContext(ctx context.Context) *Traversal {
	t, _ := ctx.Value(traversalCtxKey{}).(*Traversal)
	return t
}

type nestedCatalogingCtxKey struct{}

// WithNestedCataloging marks the context of a scan whose archive cataloger task will extract every
// archive and run the catalogers inside it. syft.CreateSBOM sets it before any task runs, so a
// cataloger that would otherwise open archives itself can leave them to the task instead.
func WithNestedCataloging(ctx context.Context) context.Context {
	return context.WithValue(ctx, nestedCatalogingCtxKey{}, true)
}

// NestedCatalogingEnabled reports whether the archive cataloger task is extracting archives in this scan.
func NestedCatalogingEnabled(ctx context.Context) bool {
	enabled, _ := ctx.Value(nestedCatalogingCtxKey{}).(bool)
	return enabled
}
