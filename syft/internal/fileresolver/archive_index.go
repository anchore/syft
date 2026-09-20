package fileresolver

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"path"
	"reflect"
	"sort"
	"strings"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal/archive"
	syftindex "github.com/anchore/syft/internal/index"
	"github.com/anchore/syft/syft/file"
)

// The index is the largest per-archive structure a scan keeps, and the only archive cost the entry
// store cannot measure: one entry is one store record but one node per path component here. So the
// index charges the scan's budget node by node and stops when refused - see ArchiveIndex.Truncated.
//
// The constants below are what one node and one file keep, deliberately over-estimated: an under-count
// lets the budget admit several times its setting.
// Test_indexChargeCoversWhatTheIndexKeeps holds them above the heap an index actually retains.
const (
	// mapSlotCost is what one string-keyed, pointer-valued pair costs a Go map beyond the pair itself:
	// control bytes, load-factor headroom, and the doubling it grows by.
	mapSlotCost = 96

	// sliceSlotCost is one pointer held in a slice grown by appending, including the headroom append
	// leaves behind it.
	sliceSlotCost = 24

	// keySplitNodeCost is one node of a key-split index - its lock, its value, and the two map headers
	// it carries whether or not it has children - rounded up. The rounding is the headroom for a key
	// that splits an existing one and so allocates a second node.
	keySplitNodeCost = 112

	// keySplitEntryCost is what one key costs the index that holds it - a node of its own, plus the
	// slot it takes in its parent's two maps. A key that splits an existing one costs a second node,
	// which is why this is charged per key rather than per distinct path through the trie.
	keySplitEntryCost = keySplitNodeCost + 2*mapSlotCost

	// nameIndexCost is what one name keeps in a base-name index on top of its node: an entry in each of
	// the forward and reverse tries, and a slot in the node slice each of those holds. The reverse
	// trie's reversed name copy is charged by length alongside this, as is the ordered view
	// AllLocations and FilesByMIMEType read.
	nameIndexCost = 2*(keySplitEntryCost+sliceSlotCost) + sliceSlotCost
)

// indexNodeCost is what one tree node keeps: the node itself - which carries a key-split index of its
// children by value - its slot in the by-path map, its slot in its parent's child list, and the slot
// it takes in its parent's child index. Name and path are substrings of the entry path, which is
// charged once per entry, so neither is counted again here.
var indexNodeCost = int64(reflect.TypeFor[indexNode]().Size()) + mapSlotCost + sliceSlotCost + keySplitEntryCost

// ArchiveIndex is a resolver over the entries of one extracted archive. It indexes archive.Entry
// values rather than file offsets, so an entry's bytes can move between memory and the overflow blob
// without the index changing.
//
// Glob lookups go through a base-name index rather than a walk: cataloger globs are overwhelmingly
// `**/*.ext` and `**/name`, answered by suffix and exact lookup respectively.
type ArchiveIndex struct {
	fileSystemID string
	archivePath  string
	root         *indexNode

	// byPath is every node by its full archive-relative path; path lookups and HasPath answer from it.
	byPath map[string]*indexNode

	// fileNames and dirNames are the global base-name indexes the search answers from: files for a
	// pattern's last segment, directories for the segment after a `**`. Values are slices because one
	// name repeats across directories.
	fileNames syftindex.PrefixSuffix[[]*indexNode]
	dirNames  syftindex.PrefixSuffix[[]*indexNode]

	store   *archive.EntryStore
	records int

	// truncated reports that the budget refused a node and the remaining entries were never indexed.
	// What was indexed before that is complete and usable.
	truncated bool

	// sorted is every file in a stable order, built once. See ordered.
	sorted []*indexNode
}

// indexNode is one file or directory in an archive's filesystem.
//
// A directory may be synthesized: archives routinely name `a/b/c.txt` without naming `a/` or `a/b/`,
// and a glob whose middle segment is a directory needs those nodes. A synthesized node has no entry.
type indexNode struct {
	name     string
	path     string
	isDir    bool
	entry    *archive.Entry
	metadata file.Metadata

	// target is the node whose entry holds this node's content: itself for an ordinary file, what it
	// points at for a link, and nil when the link dangles. Resolved once by resolveLinks.
	target *indexNode

	// children indexes this directory's children by name, which is what an exact or `name*` segment
	// looks up. childList is the same set in sorted order, for the segments that have to be matched
	// one by one and for a stable result order.
	children  syftindex.KeySplitIndex[*indexNode]
	childList []*indexNode
}

// NewFromArchiveEntries builds a resolver over the entries of one archive.
//
// An archive is its own root: entries are keyed, reported and filtered by their archive-relative
// path, and nothing here names a directory on the host. pathFilters are applied per entry as in a
// directory walk, including the prune-a-subtree answer, and are handed that same archive-relative
// path - see runPathFilters.
//
// charge is this archive's draw on the scan's resource limiter, charged per node kept. A refused
// charge truncates rather than fails the archive, as a refused entry does during extraction; a nil
// charge enforces nothing.
func NewFromArchiveEntries(fileSystemID, archivePath string, store *archive.EntryStore, charge *archive.Charge, pathFilters ...PathIndexVisitor) (*ArchiveIndex, error) {
	if store == nil {
		return nil, fmt.Errorf("no entry store for archive %q", fileSystemID)
	}

	r := &ArchiveIndex{
		fileSystemID: fileSystemID,
		archivePath:  archivePath,
		root:         &indexNode{name: "", path: "/", isDir: true},
		byPath:       map[string]*indexNode{},
		store:        store,
	}
	r.byPath["/"] = r.root

	var pruned []string
	for _, entry := range store.Entries() {
		name, ok := sanitizeEntryName(entry.Header.Name)
		if !ok {
			continue
		}
		if isPruned(name, pruned) {
			continue
		}
		switch runPathFilters(pathFilters, name, entry.Header.FileInfo()) {
		case skipEntry:
			continue
		case skipTree:
			pruned = append(pruned, name)
			continue
		case keepEntry:
		}

		if !r.add(entry, "/"+name, charge) {
			// stop rather than carrying on and admitting later entries that need fewer nodes
			r.truncated = true
			break
		}
	}

	r.finalize()
	return r, nil
}

// add puts one entry into the tree and the indexes, creating the directories its path implies. It
// reports false when the budget refused a node, which truncates the index.
func (r *ArchiveIndex) add(entry *archive.Entry, entryPath string, charge *archive.Charge) bool {
	isDir := entry.Header.FileInfo().IsDir()

	// every node and by-path key is a substring of entryPath, so the one string backs the whole chain
	// and is charged here rather than once per node
	if !charge.IndexRecord(int64(len(entryPath))) {
		return false
	}

	node, ok := r.node(entryPath, isDir, charge)
	if !ok {
		return false
	}
	if node == nil {
		// names nothing inside this archive; not a budget refusal, so the walk carries on
		return true
	}

	if node.entry != nil {
		// an archive naming the same path twice: the first entry wins
		return true
	}

	// charged before committing the entry, so a refusal never leaves a file counted but unsearchable.
	// The reverse index's key is the one string the name index allocates per name.
	if !isDir && !charge.IndexRecord(nameIndexCost+int64(len(node.name))) {
		return false
	}

	node.entry = entry
	node.metadata = r.metadataOf(entry, entryPath)
	r.records++

	if isDir {
		// already placed in dirNames when the node was created; an archive naming a directory it also
		// implies must not index it twice
		return true
	}

	r.fileNames.Update(node.name, appendNode(node))
	return true
}

// appendNode adds one node to whatever a name already holds. The index stores a slice per key because
// base names repeat across directories.
func appendNode(node *indexNode) syftindex.NodeUpdateFunc[[]*indexNode] {
	return func(current *syftindex.Node[[]*indexNode]) []*indexNode {
		return append(current.Value(), node)
	}
}

// node returns the node at the given path, creating any missing parents and charging the budget for
// each. It reports false when the budget refused a node, and a nil node for a path that names nothing
// inside the archive.
//
// Two passes: climb to the deepest ancestor already in the tree, then build down from there. The climb
// keeps the common case cheap - an entry whose parent is already placed costs one lookup however deep.
//
// Neither pass recurses: every key and name is a substring of entryPath, so a name 2,000 components
// deep costs 2,000 iterations, not 2,000 stack frames. Placing a node is still proportional to path
// length, which is why sanitizeEntryName bounds it.
func (r *ArchiveIndex) node(entryPath string, isDir bool, charge *archive.Charge) (*indexNode, bool) {
	if existing, found := r.byPath[entryPath]; found {
		return existing, true
	}

	// climb: find the deepest ancestor already in the tree, and where in entryPath it ends
	anchor, anchorEnd := r.root, 0
	for end := len(entryPath); ; {
		slash := strings.LastIndexByte(entryPath[:end], '/')
		if slash <= 0 {
			// the parent is the archive root, which is always in the tree
			break
		}
		if existing, found := r.byPath[entryPath[:slash]]; found {
			anchor, anchorEnd = existing, slash
			break
		}
		end = slash
	}

	// descend: create what is missing below the anchor. entryPath is rooted, cleaned and free of
	// trailing separators (see sanitizeEntryName), so every stretch between separators is a component.
	for start := anchorEnd + 1; start < len(entryPath); {
		end := len(entryPath)
		if i := strings.IndexByte(entryPath[start:], '/'); i >= 0 {
			end = start + i
		}

		if !charge.IndexRecord(indexNodeCost) {
			return nil, false
		}
		child := &indexNode{
			name: entryPath[start:end],
			path: entryPath[:end],
			// anything with more path below it is a directory whatever the entry itself is
			isDir: end < len(entryPath) || isDir,
		}
		anchor.children.Set(child.name, child)
		anchor.childList = append(anchor.childList, child)
		r.byPath[child.path] = child

		if child.isDir {
			// a directory the archive never named still has to be findable by name, since the segment
			// after a `**` is matched against directories - see searchFromRoot
			if !charge.IndexRecord(nameIndexCost + int64(len(child.name))) {
				return nil, false
			}
			r.dirNames.Update(child.name, appendNode(child))
		}

		anchor = child
		start = end + 1
	}

	if anchor == r.root {
		return nil, true
	}
	return anchor, true
}

// finalize sorts each directory's child list by name. The key-split indexes need no finalizing - they
// are searchable as they are built - but childList is what the segments that cannot be looked up are
// matched against, and a map's iteration order there would make results unstable.
func (r *ArchiveIndex) finalize() {
	for _, node := range r.byPath {
		sort.Slice(node.childList, func(i, j int) bool { return node.childList[i].name < node.childList[j].name })
		node.target = r.linkTarget(node)
	}
}

// maxLinkHops bounds a chain of links pointing at links. No real archive is shaped that way, and the
// bound is also what stops a cycle from being followed forever.
const maxLinkHops = 8

// linkTarget returns the node whose entry holds this node's content: the node itself when it is not a
// link, and what it points at when it is, following a chain.
//
// nil means there is nothing to read: the chain leaves the archive, ends at a directory, or does not
// end. Such a link still exists as a path, and is answered under that path with no content - which is
// all the archive says about it.
func (r *ArchiveIndex) linkTarget(node *indexNode) *indexNode {
	for hops := 0; ; hops++ {
		if node.entry == nil || node.isDir {
			return nil
		}
		header := node.entry.Header
		if header.Linkname == "" {
			return node
		}
		if hops == maxLinkHops {
			return nil
		}
		next, ok := r.byPath[resolveLinkWithinArchive(node.path, header.Linkname, header.Typeflag == tar.TypeLink)]
		if !ok {
			return nil
		}
		node = next
	}
}

// metadataOf describes one entry as a file, including the MIME type sniffed from its content, which
// FilesByMIMEType and nested archive detection both read.
func (r *ArchiveIndex) metadataOf(entry *archive.Entry, entryPath string) file.Metadata {
	var contents io.Reader
	if opened, err := r.store.Open(entry); err == nil {
		contents = opened
	}

	metadata := stereoscopeFile.NewMetadata(entry.Header, contents)
	// NewMetadata copies the header by value and its fs.FileInfo points into that copy, pinning a second
	// tar.Header per entry. Point it at the header the store already holds and charged for.
	metadata.FileInfo = entry.Header.FileInfo()
	metadata.Path = reportedPath(entryPath)

	if entry.Header.Linkname != "" {
		metadata.LinkDestination = reportedPath(
			resolveLinkWithinArchive(entryPath, entry.Header.Linkname, entry.Header.Typeflag == tar.TypeLink))
	}

	return metadata
}

// resolveLinkWithinArchive returns where a link entry points, resolved against the archive's own root
// rather than the host filesystem. linkPath is the archive-rooted path of the link itself.
//
// A hard link's target is named from the archive root (per the tar format), and an absolute symlink
// target is read as archive-absolute, so "/etc/passwd" names an entry of this archive, not the host's.
// Only a relative symlink target is joined onto the link's own directory. The leading "/" makes
// path.Join clamp climbs at the archive root, so "../../../etc/passwd" lands at "/etc/passwd" inside
// the archive.
//
// Nothing here follows the link: the result is a path in this archive's frame, resolving to an entry
// of this archive or to nothing.
func resolveLinkWithinArchive(linkPath, linkname string, hardLink bool) string {
	if hardLink || path.IsAbs(linkname) {
		return path.Join("/", linkname)
	}
	return path.Join("/", path.Dir(linkPath), linkname)
}

func (r *ArchiveIndex) Records() int { return r.records }

// Truncated reports whether the budget stopped indexing before the archive's last entry. What is
// held is usable either way, just not all of the archive.
func (r *ArchiveIndex) Truncated() bool { return r.truncated }

// Close releases the entry store, and with it the overflow blob's file handle. Readers handed out by
// this resolver borrow the store, so Close must wait until the extracted archive is torn down;
// ExtractedArchive.Cleanup calls it there. Safe to call more than once.
func (r *ArchiveIndex) Close() error {
	if r == nil || r.store == nil {
		return nil
	}
	// the reference is kept, not cleared: EntryStore.Close is idempotent, and a read arriving after
	// Close fails through the store rather than dereferencing nil
	return r.store.Close()
}

func (r *ArchiveIndex) location(node *indexNode) file.Location {
	return file.NewLocationFromCoordinates(r.coordinates(node))
}

// accessedLocation names the file at target, reached by the path of access. The two differ when a glob
// matched a link: the content is the target's, while the path the archive was searched by - and the
// one a reader will recognize - is the link's.
func (r *ArchiveIndex) accessedLocation(target, access *indexNode) file.Location {
	if access == target {
		return r.location(target)
	}
	return file.NewVirtualLocationFromCoordinates(r.coordinates(target), reportedPath(access.path))
}

func (r *ArchiveIndex) coordinates(node *indexNode) file.Coordinates {
	return file.Coordinates{
		RealPath:     reportedPath(node.path),
		FileSystemID: r.fileSystemID,
		ArchivePath:  r.archivePath,
	}
}

// reportedPath is how a path leaves this resolver: archive-relative with no leading slash, the form
// SBOMs and archive-path chains use. Nodes are keyed with the slash, which path.Dir and path.Join
// want.
func reportedPath(nodePath string) string {
	return strings.TrimPrefix(nodePath, "/")
}

// FileContentsByLocation returns a reader over the entry's content, from memory or the overflow blob.
// Either way it supports Read, Seek and ReadAt, so a nested archive is read where it lies.
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

// FilesByPath returns the files at the given paths. Directories are not files, as in every other
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

func (r *ArchiveIndex) FilesByMIMEType(types ...string) ([]file.Location, error) {
	wanted := map[string]struct{}{}
	for _, t := range types {
		wanted[t] = struct{}{}
	}

	var out []file.Location
	for _, node := range r.ordered() {
		if node.target != node {
			// only a file that holds bytes has a sniffed type; a link has none of its own. The target
			// answers for itself under its own path.
			continue
		}
		if _, ok := wanted[node.metadata.MIMEType]; !ok {
			continue
		}
		out = append(out, r.location(node))
	}
	return out, nil
}

// ordered returns the archive's files (not directories) in a stable path order.
//
// Order decides which locations group into which package when results merge into the SBOM, so an
// unstable order splits one package into several across runs.
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

// RelativeFileByPath resolves against the archive's root, the only frame an archive has.
func (r *ArchiveIndex) RelativeFileByPath(_ file.Location, userPath string) *file.Location {
	locations, err := r.FilesByPath(userPath)
	if err != nil || len(locations) == 0 {
		return nil
	}
	return &locations[0]
}

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

// requestPath puts a caller's path into the archive's frame; a leading slash is optional.
func (r *ArchiveIndex) requestPath(userPath string) string {
	if userPath == "" {
		return "/"
	}
	return path.Clean("/" + strings.TrimPrefix(userPath, "/"))
}

var _ file.Resolver = (*ArchiveIndex)(nil)

// nopCloserAt gives an entry reader the Close the resolver interface requires. The store owns the
// bytes and the overflow file, so closing a reader over them must close nothing.
type nopCloserAt struct {
	archive.ReaderAtSeeker
}

func (nopCloserAt) Close() error { return nil }
