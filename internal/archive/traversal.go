package archive

import (
	"context"
	"strings"

	"github.com/anchore/syft/syft/file"
)

// Traversal describes one level of archive nesting during recursive archive cataloging. The archive
// cataloger task places one on the context before running the cataloger sub-pipeline against an
// archive's contents, so ecosystem catalogers (e.g. java) can reconstruct nesting-aware identity
// such as colon-delimited virtual paths (e.g. "app.war:WEB-INF/lib/dep.jar") without owning the
// recursion themselves.
type Traversal struct {
	// Location is the archive file's location within its parent filesystem.
	Location file.Location

	// VirtualPath is the colon-delimited chain of archive paths from the scan root to this archive,
	// e.g. "app.war:WEB-INF/lib/dep.jar".
	VirtualPath string

	// FileSystemID is the identifier of the filesystem the archive file itself lives on (a container
	// image layer digest, or empty for a directory source), inherited unchanged down the nesting
	// chain. The nesting chain is carried by VirtualPath, not by this field.
	FileSystemID string

	// Depth is 1 for an archive found directly in the scan source, incrementing per nesting level.
	Depth int

	// Digests are the digests of the archive file itself. They are carried here because they are a
	// property of the file and not of its contents: a cataloger running against an archive's extracted
	// filesystem cannot compute them, since the archive is not inside itself. Taken once by the
	// extraction, which already has the bytes in hand.
	Digests []file.Digest

	// Parent is the traversal for the containing archive; nil at depth 1.
	Parent *Traversal
}

// VirtualPathOf returns the colon-delimited virtual path for an entry within this archive. It is
// nil-safe: with no traversal the entry path is returned unchanged, matching non-nested behavior.
// The entry path's leading slash is trimmed so chains match the historical java cataloger format,
// which joins slash-less zip entry names onto the containing archive's path.
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

// WithLimiter returns a context carrying the scan's archive limiter, so a cataloger running within
// the recursive walk can read the scan's live draw on the memory and disk budgets (Limiter.InUse) -
// the same totals the limits are enforced against. Carried on the context rather than copied onto
// each Traversal so there is one source of truth for the charge, not a snapshot per level.
func WithLimiter(ctx context.Context, l *Limiter) context.Context {
	return context.WithValue(ctx, limiterCtxKey{}, l)
}

// LimiterFromContext returns the scan's archive limiter, or nil when the current pass is not running
// within the recursive archive walk.
func LimiterFromContext(ctx context.Context) *Limiter {
	l, _ := ctx.Value(limiterCtxKey{}).(*Limiter)
	return l
}

type traversalCtxKey struct{}

// WithTraversal returns a context carrying the given archive traversal.
func WithTraversal(ctx context.Context, t *Traversal) context.Context {
	return context.WithValue(ctx, traversalCtxKey{}, t)
}

// TraversalFromContext returns the archive traversal on the context, or nil when the current
// cataloging pass is not running within an archive.
func TraversalFromContext(ctx context.Context) *Traversal {
	t, _ := ctx.Value(traversalCtxKey{}).(*Traversal)
	return t
}
