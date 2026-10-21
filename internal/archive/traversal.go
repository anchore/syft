package archive

import (
	"context"
	"path"
	"slices"
	"strings"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// Traversal describes the archive whose contents a cataloger is running against. The archive
// cataloger task puts one on the context before running catalogers inside an archive, so a cataloger
// such as java can describe the archive it is inside without owning the recursion.
type Traversal struct {
	// Location is the archive file's location within its parent filesystem, including the access path
	// it was reached by, so VirtualPath(Location) is the chain from the scan root as seen through that
	// access path. The files inside it extend its real coordinates instead (see ContainerPath).
	Location file.Location

	// Digests are of the archive file itself, taken during extraction; a cataloger running inside the
	// archive cannot compute them since the archive is not inside itself.
	Digests []file.Digest

	// Parent is the traversal of the archive this one is nested in, nil for an archive at the scan root.
	Parent *Traversal

	// Packages are those the catalogers found describing this archive (located at it), filled in once
	// they have run. Catalogers inside a nested archive read them through Parent, as java does to link a
	// nested jar to the jar that holds it.
	Packages []pkg.Package
}

// FullPathIn is the full path of the entry at entryPath inside the archive whose full path is
// containerPath, or entryPath itself for a blank containerPath (the scan root).
func FullPathIn(containerPath, entryPath string) string {
	if containerPath == "" {
		return entryPath
	}
	if !strings.HasPrefix(entryPath, "/") {
		entryPath = "/" + entryPath
	}
	// cleaning an already clean path allocates nothing
	return containerPath + file.ArchivePathSeparator + path.Clean(entryPath)[1:]
}

// OwnerContainers are the containers a package owns files within: the container of each of its
// locations, each once, as coordinates whose FullPath is the container's full path (blank at the scan
// root). A package without locations owns files at the scan root. See OwnedCoordinates.
func OwnerContainers(p pkg.Package) []file.Coordinates {
	var out []file.Coordinates
	for _, l := range p.Locations.ToUnorderedSlice() {
		c := file.Coordinates{FileSystemID: l.FileSystemID}
		if container := ContainerPath(l.Coordinates); container != "" {
			c.RealPath, c.FullPath = l.RealPath, container
		}
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		out = append(out, file.Coordinates{})
	}
	return out
}

// OwnedCoordinates are the coordinates of the file at ownedPath within container, one of
// OwnerContainers. At the scan root the path may still need resolving (it may pass through links).
func OwnedCoordinates(container file.Coordinates, ownedPath string) file.Coordinates {
	if container.FullPath == "" {
		return file.Coordinates{RealPath: ownedPath, FileSystemID: container.FileSystemID}
	}
	return file.Coordinates{
		RealPath:     container.RealPath,
		FileSystemID: container.FileSystemID,
		FullPath:     FullPathIn(container.FullPath, ownedPath),
	}
}

// FullTraversalArchivePath is the archive's own full path, which is the ContainerPath of every file inside it. Outside
// any archive (a nil Traversal) it is blank, as for files on the scanned filesystem.
func (t *Traversal) FullTraversalArchivePath() string {
	if t == nil {
		return ""
	}
	return t.Location.FullNestedPath()
}

// ContainerPath returns the full path of the archive directly holding the file at c, or blank for a
// file on the scanned filesystem, whether or not its FullPath is set.
func ContainerPath(c file.Coordinates) string {
	entries, ok := archiveEntries(c)
	if !ok {
		return ""
	}
	if i := strings.LastIndex(entries, file.ArchivePathSeparator); i >= 0 {
		return c.RealPath + file.ArchivePathSeparator + entries[:i]
	}
	return c.RealPath
}

// archiveEntries is the "!/"-delimited chain of entry paths after RealPath, reporting false for a file
// not inside an archive. RealPath is split off first, so a "!/" in it is not taken for a boundary.
func archiveEntries(c file.Coordinates) (string, bool) {
	remain, ok := strings.CutPrefix(c.FullNestedPath(), c.RealPath)
	if !ok {
		return "", false
	}
	return strings.CutPrefix(remain, file.ArchivePathSeparator)
}

// VirtualPath returns the colon-delimited chain of archives from the scan root to loc, ending in loc
// itself as accessed: "app.war:WEB-INF/lib/dep.jar". Outside any archive it is the location's path
// unchanged. In an entry name '%' is escaped as "%25" and then ':' as "%3A", so splitting on ':'
// recovers the archive boundaries and no two entry names share an escaped form. Leading slashes are
// dropped to match the java cataloger, which joins slash-less zip entry names onto the containing
// archive's path.
func VirtualPath(loc file.Location) string {
	accessPath := loc.AccessPath
	if accessPath == "" {
		accessPath = loc.FullNestedPath()
	}
	entries, ok := archiveEntries(loc.Coordinates)
	if !ok {
		return accessPath
	}
	segments := strings.Split(entries, file.ArchivePathSeparator)
	if rest, ok := strings.CutPrefix(accessPath, ContainerPath(loc.Coordinates)); ok && strings.HasPrefix(rest, file.ArchivePathSeparator) {
		accessPath = rest[len(file.ArchivePathSeparator):]
	}
	segments[len(segments)-1] = accessPath
	for i, s := range segments {
		segments[i] = strings.TrimPrefix(escapeEntryPath(s), "/")
	}
	return loc.RealPath + ":" + strings.Join(segments, ":")
}

var entryPathEscaper = strings.NewReplacer("%", "%25", ":", "%3A")

func escapeEntryPath(p string) string {
	if !strings.ContainsAny(p, "%:") {
		return p
	}
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
