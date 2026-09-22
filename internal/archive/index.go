package archive

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	syftindex "github.com/anchore/syft/internal/index"
	"github.com/anchore/syft/syft/file"
)

// Index is a file.Resolver over one extracted archive's entries.
//
// Paths are archive-relative. Nearly every cataloger glob is `**/<name>` or `**/*<suffix>`, so files
// are indexed by base name and a pattern whose last segment fixes a name, prefix or suffix is
// narrowed to those files before doublestar decides; any other pattern is matched against every file.
type Index struct {
	fileSystemID string
	archivePath  string
	store        *EntryStore

	// byPath holds every file and directory by rooted path, including directories the archive never
	// listed but that entry paths imply
	byPath map[string]*node

	// files holds every file the archive listed, in path order
	files []*node

	// names indexes files by base name
	names syftindex.PrefixSuffix[[]*node]
}

type node struct {
	path     string // rooted, e.g. "/META-INF/MANIFEST.MF"
	isDir    bool
	entry    *Entry // nil for a directory the archive never listed
	metadata file.Metadata

	// target is the node whose entry holds this node's content: itself for a regular file, the
	// resolved node for a link, and nil for a link that leads nowhere inside this archive
	target *node
}

var _ file.Resolver = (*Index)(nil)

// NewIndex builds a resolver over the store's entries whose locations carry the given fileSystemID
// and archivePath.
func NewIndex(store *EntryStore, fileSystemID, archivePath string) *Index {
	r := &Index{
		fileSystemID: fileSystemID,
		archivePath:  archivePath,
		store:        store,
		byPath:       map[string]*node{"/": {path: "/", isDir: true}},
	}
	for _, entry := range store.Entries() {
		r.add(entry)
	}
	sort.Slice(r.files, func(i, j int) bool { return r.files[i].path < r.files[j].path })
	for _, n := range r.byPath {
		n.target = r.linkTarget(n)
	}
	return r
}

// add places an entry at its path, creating the directories the path implies. The first entry at a
// path wins.
func (r *Index) add(entry *Entry) {
	entryPath := path.Clean("/" + entry.Header.Name)
	if entryPath == "/" {
		return
	}
	for i := 1; i < len(entryPath); i++ {
		if entryPath[i] == '/' {
			r.nodeAt(entryPath[:i], true)
		}
	}

	n := r.nodeAt(entryPath, entry.Header.FileInfo().IsDir())
	if n.entry != nil {
		return
	}
	n.entry = entry
	n.metadata = r.metadataOf(entry, entryPath)
	if n.isDir {
		return
	}
	r.files = append(r.files, n)
	r.names.Update(path.Base(entryPath), func(current *syftindex.Node[[]*node]) []*node {
		return append(current.Value(), n)
	})
}

func (r *Index) nodeAt(p string, isDir bool) *node {
	if n, ok := r.byPath[p]; ok {
		return n
	}
	n := &node{path: p, isDir: isDir}
	r.byPath[p] = n
	return n
}

// maxLinkHops bounds a chain of links pointing at links, which is also what ends a cycle.
const maxLinkHops = 8

func (r *Index) linkTarget(n *node) *node {
	for hops := 0; hops <= maxLinkHops; hops++ {
		if n.entry == nil || n.isDir {
			return nil
		}
		if n.entry.Header.Linkname == "" {
			return n
		}
		next, ok := r.byPath[linkDestination(n.path, n.entry.Header)]
		if !ok {
			return nil
		}
		n = next
	}
	return nil
}

// linkDestination is the rooted path a link points at inside the archive. A hard link names its
// target from the archive root, as does an absolute symlink, so "/etc/passwd" is an entry of this
// archive and never the host's. A relative symlink is joined onto the link's own directory, and
// cleaning against the root keeps "../../x" inside the archive.
func linkDestination(linkPath string, hdr tar.Header) string {
	if hdr.Typeflag == tar.TypeLink || path.IsAbs(hdr.Linkname) {
		return path.Join("/", hdr.Linkname)
	}
	return path.Join(path.Dir(linkPath), hdr.Linkname)
}

func (r *Index) metadataOf(entry *Entry, entryPath string) file.Metadata {
	metadata := stereoscopeFile.NewMetadata(entry.Header, r.store.Open(entry))
	// NewMetadata copies the header and points FileInfo into the copy; share the one the store holds
	metadata.FileInfo = entry.Header.FileInfo()
	metadata.Path = reportedPath(entryPath)
	if entry.Header.Linkname != "" {
		metadata.LinkDestination = reportedPath(linkDestination(entryPath, entry.Header))
	}
	return metadata
}

// reportedPath is how paths leave the resolver: archive-relative with no leading slash.
func reportedPath(rooted string) string {
	return strings.TrimPrefix(rooted, "/")
}

func rootedPath(userPath string) string {
	return path.Clean("/" + userPath)
}

func (r *Index) coordinates(n *node) file.Coordinates {
	return file.Coordinates{
		RealPath:     reportedPath(n.path),
		FileSystemID: r.fileSystemID,
		ArchivePath:  r.archivePath,
	}
}

// locationOf names a node by its own path.
func (r *Index) locationOf(n *node) file.Location {
	return file.NewLocationFromCoordinates(r.coordinates(n))
}

// resolvedLocation names the file behind a node: a link is reported at its target's path with the
// link's own path as the access path, and a link leading nowhere is reported as itself.
func (r *Index) resolvedLocation(n *node) file.Location {
	if n.target == nil || n.target == n {
		return r.locationOf(n)
	}
	return file.NewVirtualLocationFromCoordinates(r.coordinates(n.target), reportedPath(n.path))
}

func (r *Index) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	n, ok := r.byPath[rootedPath(location.RealPath)]
	if !ok || n.entry == nil {
		return nil, fmt.Errorf("no archive entry for path=%q", location.RealPath)
	}
	return entryReader{r.store.Open(n.entry)}, nil
}

func (r *Index) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	n, ok := r.byPath[rootedPath(location.RealPath)]
	if !ok {
		return file.Metadata{}, fmt.Errorf("no archive entry for path=%q", location.RealPath)
	}
	return n.metadata, nil
}

func (r *Index) HasPath(userPath string) bool {
	_, ok := r.byPath[rootedPath(userPath)]
	return ok
}

func (r *Index) FilesByPath(paths ...string) ([]file.Location, error) {
	var out []file.Location
	seen := map[*node]struct{}{}
	for _, userPath := range paths {
		n, ok := r.byPath[rootedPath(userPath)]
		if !ok || n.isDir || n.entry == nil {
			continue
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, r.resolvedLocation(n))
	}
	return out, nil
}

func (r *Index) FilesByGlob(patterns ...string) ([]file.Location, error) {
	matched := map[*node]struct{}{}
	for _, pattern := range patterns {
		pattern = strings.TrimLeft(pattern, "/")
		if pattern == "" {
			continue
		}
		for _, n := range r.globCandidates(pattern) {
			ok, err := doublestar.Match(pattern, reportedPath(n.path))
			if err != nil {
				return nil, fmt.Errorf("invalid glob %q: %w", pattern, err)
			}
			if ok {
				matched[n] = struct{}{}
			}
		}
	}

	var out []file.Location
	for _, n := range onePathPerFile(matched) {
		out = append(out, r.resolvedLocation(n))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RealPath != out[j].RealPath {
			return out[i].RealPath < out[j].RealPath
		}
		return out[i].AccessPath < out[j].AccessPath
	})
	return out, nil
}

// globMetacharacters are the glob metacharacters other than `*` itself.
const globMetacharacters = `?[]{}\`

// globCandidates narrows the files a pattern can match by its last segment: an exact name, `*suffix`
// or `prefix*` is looked up in the name index. Any other shape has every file as a candidate.
func (r *Index) globCandidates(pattern string) []*node {
	last := pattern[strings.LastIndexByte(pattern, '/')+1:]
	if strings.ContainsAny(last, globMetacharacters) || strings.Count(last, "*") > 1 {
		return r.files
	}
	switch star := strings.IndexByte(last, '*'); {
	case star < 0:
		return r.names.Get(last)
	case star == 0:
		return flatten(r.names.BySuffix(last[1:]))
	case star == len(last)-1:
		return flatten(r.names.ByPrefix(last[:star]))
	}
	return r.files
}

func flatten(groups [][]*node) []*node {
	var out []*node
	for _, group := range groups {
		out = append(out, group...)
	}
	return out
}

// onePathPerFile keeps one matched path per file. Several paths can name the same content, such as
// a link and its target, and a resolver answers with one: the file's own path when it matched,
// otherwise the lowest-sorting link. A link leading nowhere stands as its own file.
func onePathPerFile(matched map[*node]struct{}) []*node {
	best := map[*node]*node{}
	for n := range matched {
		key := n.target
		if key == nil {
			key = n
		}
		current, seen := best[key]
		if !seen || n == key || (current != key && n.path < current.path) {
			best[key] = n
		}
	}
	out := make([]*node, 0, len(best))
	for _, n := range best {
		out = append(out, n)
	}
	return out
}

func (r *Index) FilesByMIMEType(types ...string) ([]file.Location, error) {
	wanted := map[string]struct{}{}
	for _, t := range types {
		wanted[t] = struct{}{}
	}
	var out []file.Location
	for _, n := range r.files {
		// only a file holding bytes has a type of its own; a link's target answers for itself
		if n.target != n {
			continue
		}
		if _, ok := wanted[n.metadata.MIMEType]; ok {
			out = append(out, r.locationOf(n))
		}
	}
	return out, nil
}

// RelativeFileByPath resolves against the archive root, the only frame an archive has.
func (r *Index) RelativeFileByPath(_ file.Location, userPath string) *file.Location {
	locations, _ := r.FilesByPath(userPath)
	if len(locations) == 0 {
		return nil
	}
	return &locations[0]
}

func (r *Index) AllLocations(ctx context.Context) <-chan file.Location {
	out := make(chan file.Location)
	go func() {
		defer close(out)
		for _, n := range r.files {
			select {
			case out <- r.locationOf(n):
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// entryReader gives an entry's reader the Close the resolver interface requires. The store owns the
// bytes, so there is nothing to close.
type entryReader struct {
	ReaderAtSeeker
}

func (entryReader) Close() error { return nil }
