package fileresolver

import (
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal/archive"
	syftindex "github.com/anchore/syft/internal/index"
	"github.com/anchore/syft/syft/file"
)

// ArchiveIndex is a resolver over the entries of one extracted archive, indexed by the entries
// themselves rather than by offsets into a file.
//
// It exists because the resolver it stands beside, ArchiveTar, can only index content that is already
// on disk: its index IS the tar's seek offsets, so every archive paid for a tar write and a tar walk
// before a cataloger could read a byte. Here the index is over archive.Entry values whose bytes may be
// in memory or in an overflow blob, and which may move between the two without the index noticing.
//
// Lookups go through a key-split index rather than a walk. A cataloger's globs are overwhelmingly
// `**/*.ext` and `**/name`, and both are answered by a lookup keyed on the base name - by suffix for
// an extension, exactly for a name - instead of by matching every path in the archive.
type ArchiveIndex struct {
	fileSystemID string
	archivePath  string
	root         *indexNode

	// byPath is every node by its full archive-relative path, which is what a path lookup wants and
	// what HasPath answers from.
	byPath map[string]*indexNode

	// fileNames and dirNames are the global base-name indexes the glob fast paths use. The values are
	// slices because a name repeats across directories.
	fileNames syftindex.PrefixSuffix[[]*indexNode]
	dirNames  syftindex.PrefixSuffix[[]*indexNode]

	store     *archive.EntryStore
	records   int
	truncated bool

	// sorted is every file in a stable order, built once. See ordered.
	sorted []*indexNode
}

// indexNode is one file or directory in an archive's filesystem.
//
// A directory may be synthesized: archives routinely name `a/b/c.txt` without ever naming `a/` or
// `a/b/`, and a resolver that only knew the named entries could not answer a glob whose middle
// segment is a directory. A synthesized node has no entry and no content.
type indexNode struct {
	name     string
	path     string
	isDir    bool
	entry    *archive.Entry
	metadata file.Metadata
	parent   *indexNode

	children  syftindex.KeySplitIndex[*indexNode]
	childList []*indexNode
}

// NewFromArchiveEntries builds a resolver over the entries of one archive.
//
// rootPath is what every entry's path is reported relative to, matching what the tar-backed resolver
// reports, so a location's path is archive-relative rather than naming the scan's scratch space.
// pathFilters are applied per entry exactly as they are for a directory walk, including the
// prune-a-subtree answer.
func NewFromArchiveEntries(rootDir, fileSystemID, archivePath string, store *archive.EntryStore, truncated bool, pathFilters ...PathIndexVisitor) (*ArchiveIndex, error) {
	if store == nil {
		return nil, fmt.Errorf("no entry store for archive %q", fileSystemID)
	}

	// Two frames, and they are not interchangeable. Nodes are keyed and reported by their
	// archive-relative path, because that is what belongs in an SBOM - a location naming the scan's
	// scratch directory would leak a temp path into published output, and the filesystem id chain is
	// composed from these paths. Path filters, on the other hand, are built against the real
	// directory, so they are handed the absolute path.
	rootPath := treeRoot(rootDir)
	r := &ArchiveIndex{
		fileSystemID: fileSystemID,
		archivePath:  archivePath,
		root:         &indexNode{name: "", path: "/", isDir: true},
		byPath:       map[string]*indexNode{},
		store:        store,
		truncated:    truncated,
	}
	r.byPath["/"] = r.root

	var pruned []string
	for _, entry := range store.Entries() {
		name, ok := sanitizeEntryName(entry.Header.Name)
		if !ok {
			continue
		}
		absPath := path.Join(rootPath, name)

		if isPruned(absPath, pruned) {
			continue
		}
		switch runPathFilters(pathFilters, rootDir, absPath, entry.Header.FileInfo()) {
		case skipEntry:
			continue
		case skipTree:
			pruned = append(pruned, absPath)
			continue
		case keepEntry:
		}

		r.add(entry, "/"+name)
	}

	return r, nil
}

// add puts one entry into the tree and the indexes, creating whatever directories its path implies.
func (r *ArchiveIndex) add(entry *archive.Entry, entryPath string) {
	isDir := entry.Header.FileInfo().IsDir()
	node := r.node(entryPath, isDir)
	if node == nil {
		return
	}

	if node.entry != nil {
		// a crafted archive naming the same path twice: the first entry is the one this filesystem
		// has, matching the tar-backed resolver, which cannot add a second node at one path either
		return
	}

	node.entry = entry
	node.metadata = r.metadataOf(entry, entryPath)
	r.records++

	if isDir {
		r.dirNames.Update(node.name, appendNode(node))
		return
	}
	r.fileNames.Update(node.name, appendNode(node))
}

func appendNode(node *indexNode) syftindex.NodeUpdateFunc[[]*indexNode] {
	return func(current *syftindex.Node[[]*indexNode]) []*indexNode {
		return append(current.Value(), node)
	}
}

// node returns the node at the given path, creating it and any missing parent directories.
func (r *ArchiveIndex) node(entryPath string, isDir bool) *indexNode {
	if existing, ok := r.byPath[entryPath]; ok {
		return existing
	}

	parentPath := path.Dir(entryPath)
	if parentPath == entryPath {
		// cannot climb any further without leaving the archive
		return nil
	}
	parent := r.node(parentPath, true)
	if parent == nil {
		return nil
	}

	node := &indexNode{
		name:   path.Base(entryPath),
		path:   entryPath,
		isDir:  isDir,
		parent: parent,
	}
	parent.children.Set(node.name, node)
	parent.childList = append(parent.childList, node)
	r.byPath[entryPath] = node

	if isDir && node.entry == nil {
		// a directory the archive never named still has to be findable by name, since a glob's middle
		// segment may be exactly it
		r.dirNames.Update(node.name, appendNode(node))
	}
	return node
}

// metadataOf describes one entry as a file in the archive's filesystem, including the MIME type
// sniffed from its content - which is what FilesByMIMEType answers from, and what archive detection
// one level down depends on.
func (r *ArchiveIndex) metadataOf(entry *archive.Entry, entryPath string) file.Metadata {
	var contents io.Reader
	if opened, err := r.store.Open(entry); err == nil {
		contents = opened
	}

	metadata := stereoscopeFile.NewMetadata(entry.Header, contents)
	metadata.Path = reportedPath(entryPath)

	if entry.Header.Linkname != "" {
		relative := path.Clean(entry.Header.Linkname)
		if !path.IsAbs(relative) {
			relative = path.Join("/", path.Dir(entryPath), entry.Header.Linkname)
		}
		// resolved in archive-relative space, where path.Join clamps a climb at the root, so a target
		// naming the host filesystem lands somewhere inside this archive or nowhere at all
		metadata.LinkDestination = reportedPath(relative)
	}

	return metadata
}

// Records reports how many of the archive's entries this filesystem holds.
func (r *ArchiveIndex) Records() int { return r.records }

// IndexTruncated reports that the archive's content ended before the archive did.
func (r *ArchiveIndex) IndexTruncated() bool { return r.truncated }

// Close releases the entry store this index was built over, and with it the overflow blob's file
// handle. Readers handed out by this resolver borrow the store, so the index must not be closed until
// the extracted archive is torn down - which is exactly when ExtractedArchive.Cleanup calls it, after
// the sub-pipeline and after recursion. Safe to call more than once.
func (r *ArchiveIndex) Close() error {
	if r == nil || r.store == nil {
		return nil
	}
	// the store reference is kept, not cleared: EntryStore.Close is itself idempotent, and a read that
	// arrives after Close then fails gracefully through the store rather than dereferencing a nil one.
	return r.store.Close()
}

func (r *ArchiveIndex) location(node *indexNode) file.Location {
	return file.NewLocationFromCoordinates(file.Coordinates{
		RealPath:     reportedPath(node.path),
		FileSystemID: r.fileSystemID,
		ArchivePath:  r.archivePath,
	})
}

// reportedPath is how a path leaves this resolver: archive-relative and with no leading slash, which
// is the form the tar-backed resolver reports and therefore the form already in published SBOMs and in
// every filesystem-id chain composed from one. Nodes are keyed with the slash, because that is what
// path.Dir and path.Join want.
func reportedPath(nodePath string) string {
	return strings.TrimPrefix(nodePath, "/")
}

// FileContentsByLocation returns a reader over the entry's content, from memory or from the overflow
// blob as it currently stands. The reader is Read, Seek and ReadAt either way, so a nested archive is
// read where it lies.
func (r *ArchiveIndex) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	node, ok := r.byPath[r.requestPath(location.RealPath)]
	if !ok || node.entry == nil {
		return nil, fmt.Errorf("no archive entry for path=%q", location.RealPath)
	}
	reader, err := r.store.Open(node.entry)
	if err != nil {
		return nil, err
	}
	return overflowEntryReader{nopCloserAt{reader}}, nil
}

// FileMetadataByLocation returns what was recorded for the entry when it was indexed.
func (r *ArchiveIndex) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	node, ok := r.byPath[r.requestPath(location.RealPath)]
	if !ok {
		return file.Metadata{}, fmt.Errorf("no archive entry for path=%q", location.RealPath)
	}
	return node.metadata, nil
}

// HasPath reports whether the archive holds anything at that path, file or directory.
func (r *ArchiveIndex) HasPath(userPath string) bool {
	_, ok := r.byPath[r.requestPath(userPath)]
	return ok
}

// FilesByPath returns the files at the given paths. Directories are not files, matching every other
// resolver.
func (r *ArchiveIndex) FilesByPath(paths ...string) ([]file.Location, error) {
	var out []file.Location
	seen := map[string]struct{}{}
	for _, userPath := range paths {
		node, ok := r.byPath[r.requestPath(userPath)]
		if !ok || node.isDir || node.entry == nil {
			continue
		}
		if _, dup := seen[node.path]; dup {
			continue
		}
		seen[node.path] = struct{}{}
		out = append(out, r.location(node))
	}
	return out, nil
}

// FilesByMIMEType returns the files whose sniffed content type is one of the given types.
func (r *ArchiveIndex) FilesByMIMEType(types ...string) ([]file.Location, error) {
	wanted := map[string]struct{}{}
	for _, t := range types {
		wanted[t] = struct{}{}
	}

	var out []file.Location
	for _, node := range r.ordered() {
		if node.entry == nil {
			continue
		}
		if _, ok := wanted[node.metadata.MIMEType]; !ok {
			continue
		}
		out = append(out, r.location(node))
	}
	return out, nil
}

// ordered returns the archive's files in a stable order.
//
// Every answer this resolver gives has to be ordered, because a resolver that returns the same set in
// a different order each run is not the same resolver twice. The archive walk enters archives in the
// order they are handed to it, and what it finds inside them is merged into one shared SBOM - so the
// order decides which locations end up grouped into which package. Measured on trinodb/trino, whose
// plugin jars are hard links to one another: unordered, one libzstd with 24 locations became three
// libzstd packages holding 6, 9 and 9 of the same 24.
//
// Files are kept rather than every node, since every caller of this wants files.
func (r *ArchiveIndex) ordered() []*indexNode {
	if r.sorted != nil {
		return r.sorted
	}
	out := make([]*indexNode, 0, len(r.byPath))
	for _, node := range r.byPath {
		if node.isDir {
			continue
		}
		out = append(out, node)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	r.sorted = out
	return out
}

// RelativeFileByPath resolves a path relative to the archive's root, which is the only frame an
// archive has.
func (r *ArchiveIndex) RelativeFileByPath(_ file.Location, userPath string) *file.Location {
	locations, err := r.FilesByPath(userPath)
	if err != nil || len(locations) == 0 {
		return nil
	}
	return &locations[0]
}

// AllLocations returns every file in the archive.
func (r *ArchiveIndex) AllLocations(ctx context.Context) <-chan file.Location {
	out := make(chan file.Location)
	go func() {
		defer close(out)
		for _, node := range r.ordered() {
			if node.entry == nil {
				continue
			}
			select {
			case out <- r.location(node):
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// requestPath puts a caller's path into the archive's frame: a path may arrive absolute (the way a
// cataloger writes it) or already rooted, and both name the same entry.
func (r *ArchiveIndex) requestPath(userPath string) string {
	if userPath == "" {
		return "/"
	}
	return path.Clean("/" + strings.TrimPrefix(userPath, "/"))
}

var _ file.Resolver = (*ArchiveIndex)(nil)

// nopCloserAt gives an entry reader the Close the resolver interface asks for. The store owns the
// bytes and the overflow file, so closing a reader over them must not close anything.
type nopCloserAt struct {
	archive.ReaderAtSeeker
}

func (nopCloserAt) Close() error { return nil }
