package archive

import (
	"context"
	"strings"

	"github.com/anchore/syft/syft/file"
)

// Traversal describes one level of archive nesting. The archive cataloger task places one on the
// context before running the sub-pipeline against an archive's contents, so ecosystem catalogers
// (e.g. java) can reconstruct nesting-aware identity like "app.war:WEB-INF/lib/dep.jar" without
// owning the recursion.
type Traversal struct {
	// Location is the archive file's location within its parent filesystem.
	Location file.Location

	// VirtualPath is the colon-delimited chain of archive paths from the scan root to this archive,
	// e.g. "app.war:WEB-INF/lib/dep.jar".
	VirtualPath string

	// Digests are of the archive file itself, taken once during extraction. A cataloger running against
	// the extracted filesystem cannot compute them, since the archive is not inside itself.
	Digests []file.Digest
}

// VirtualPathOf returns the colon-delimited virtual path for an entry within this archive, or the
// entry path unchanged on a nil traversal. The leading slash is trimmed to match the java cataloger
// format, which joins slash-less zip entry names onto the containing archive's path.
func (t *Traversal) VirtualPathOf(entryPath string) string {
	if t == nil {
		return entryPath
	}
	entryPath = strings.ReplaceAll(entryPath, ":", "%3A")
	if t.VirtualPath == "" {
		return entryPath
	}
	return t.VirtualPath + ":" + strings.TrimPrefix(entryPath, "/")
}

type limiterCtxKey struct{}

// WithLimiter returns a context carrying the scan's archive limiter, so a cataloger inside the walk
// can read the live draw on the budgets (Limiter.InUse). It rides the context rather than each
// Traversal so every level reads one shared total.
func WithLimiter(ctx context.Context, l *Limiter) context.Context {
	return context.WithValue(ctx, limiterCtxKey{}, l)
}

// LimiterFromContext returns the scan's archive limiter, or nil outside the recursive archive walk.
func LimiterFromContext(ctx context.Context) *Limiter {
	l, _ := ctx.Value(limiterCtxKey{}).(*Limiter)
	return l
}

type traversalCtxKey struct{}

// WithTraversal returns a context carrying the given archive traversal.
func WithTraversal(ctx context.Context, t *Traversal) context.Context {
	return context.WithValue(ctx, traversalCtxKey{}, t)
}

// TraversalFromContext returns the archive traversal on the context, or nil outside an archive.
func TraversalFromContext(ctx context.Context) *Traversal {
	t, _ := ctx.Value(traversalCtxKey{}).(*Traversal)
	return t
}
