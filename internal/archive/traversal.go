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
	// Location is the archive file's location within its parent filesystem, including the access path
	// it was reached by. Its ArchivePath names the archives above it, so VirtualPath(Location) is the
	// full chain from the scan root as seen through that access path. The ArchivePath of the files
	// inside it is built from the real path instead.
	Location file.Location

	// Digests are of the archive file itself, taken during extraction; a cataloger running inside the
	// archive cannot compute them since the archive is not inside itself.
	Digests []file.Digest
}

// ContentsArchivePath is the ArchivePath every file inside the archive carries: the chain to it, built
// from real paths. Outside any archive (a nil Traversal) it is blank, as for files at the scan root.
func (t *Traversal) ContentsArchivePath() string {
	if t == nil {
		return ""
	}
	return VirtualPath(file.NewLocationFromCoordinates(t.Location.Coordinates))
}

// VirtualPath returns the colon-delimited chain of archives from the scan root to loc, ending in loc
// itself: "app.war:WEB-INF/lib/dep.jar". Outside any archive it is the location's path unchanged. In an
// entry name '%' is escaped as "%25" and then ':' as "%3A", so splitting on ':' recovers the archive
// boundaries and no two entry names share an escaped form. The leading slash is dropped to match the
// java cataloger, which joins slash-less zip entry names onto the containing archive's path.
func VirtualPath(loc file.Location) string {
	if loc.ArchivePath == "" {
		return loc.Path()
	}
	return loc.ArchivePath + ":" + strings.TrimPrefix(escapeEntryPath(loc.Path()), "/")
}

var entryPathEscaper = strings.NewReplacer("%", "%25", ":", "%3A")

func escapeEntryPath(p string) string {
	return entryPathEscaper.Replace(p)
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

type budgetCtxKey struct{}

// WithBudget sets the decompression budget that Extract spends from, for this archive and every archive
// extracted beneath it.
func WithBudget(ctx context.Context, b *Budget) context.Context {
	return context.WithValue(ctx, budgetCtxKey{}, b)
}

func budgetFromContext(ctx context.Context) *Budget {
	b, _ := ctx.Value(budgetCtxKey{}).(*Budget)
	return b
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
