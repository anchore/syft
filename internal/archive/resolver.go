package archive

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/mholt/archives"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	intFile "github.com/anchore/syft/internal/file"
	syftindex "github.com/anchore/syft/internal/index"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/tmpdir"
	"github.com/anchore/syft/syft/file"
)

// Resolver is one archive opened as its own filesystem: a file.Resolver over the entries Extract fed
// into it, holding their content within the scan's limits.
//
// Paths are archive-relative with no leading slash. Files and directories are indexed by base name and
// linked into a tree, so a glob is narrowed to the names its segments fix and verified up the parent
// chain; see glob.go.
type Resolver struct {
	// Digests are of the archive file itself.
	Digests []file.Digest

	// Truncated reports that the resolver covers only part of the archive, and TruncatedReason says why:
	// the disk limit or the decompression budget stopped extraction early, or an entry was too large.
	Truncated       bool
	TruncatedReason string

	fileSystemID string
	archivePath  string
	charge       *charge
	budget       *Budget

	// content is held in memory while the memory limit admits it and in one spill file once it does
	// not. The file is created on first use, so an archive that stays in memory never touches the
	// filesystem, and blobs are located in it by offset with no framing of their own.
	tempDir *tmpdir.TempDir
	held    []*blob // blobs in memory, in the order they were added
	file    *os.File
	remove  func()
	written int64
	chunk   []byte

	// byPath holds every file and directory by rooted path, including directories the archive never
	// listed but that entry paths imply
	byPath map[string]*node

	// files holds every file the archive listed, in path order once finished
	files []*node

	// names and dirs index files and directories by base name, for globs
	names syftindex.PrefixSuffix[[]*node]
	dirs  syftindex.PrefixSuffix[[]*node]
}

type node struct {
	path     string // rooted, e.g. "/META-INF/MANIFEST.MF"
	name     string // the last component of path
	isDir    bool
	header   *tar.Header // nil for a directory the archive never listed
	content  blob
	metadata file.Metadata

	// the tree the paths spell out, so a glob is matched up the chain and a directory's files are
	// found beneath it
	parent   *node
	children []*node

	// target is the node whose content this node reads: itself for a regular file, the resolved node
	// for a link, and nil for a link that leads nowhere inside this archive
	target *node
}

var _ file.Resolver = (*Resolver)(nil)

// newResolver returns an empty resolver whose locations carry the given fileSystemID and archivePath,
// spilling into the scan's temp root when ctx carries one (see internal/tmpdir).
func newResolver(ctx context.Context, fileSystemID, archivePath string, charge *charge) *Resolver {
	return &Resolver{
		fileSystemID: fileSystemID,
		archivePath:  archivePath,
		charge:       charge,
		budget:       budgetFromContext(ctx),
		tempDir:      tmpdir.FromContext(ctx),
		byPath:       map[string]*node{"/": {path: "/", isDir: true}},
	}
}

// Cleanup removes everything the archive holds on disk and releases its charge against the limiter.
// Readers handed out before are no longer valid. Safe to call more than once.
func (r *Resolver) Cleanup() {
	if r == nil {
		return
	}
	r.releaseStorage()
	r.charge.release()
}

// approxIndexBytesPerEntry estimates what holding one node costs beyond its content: the node, its
// header, and its path map and name index slots. It is charged for every node an entry creates,
// including the directories its path implies, so an archive of many tiny entries or of a few entries
// with very deep paths is still bounded by the limits.
const approxIndexBytesPerEntry = 2 * 1024

func approxIndexBytes(hdr tar.Header) int64 {
	return approxIndexBytesPerEntry + int64(len(hdr.Name)+len(hdr.Linkname))
}

// add stores and indexes one entry, reading its content in full now since archive readers are
// sequential. Reaching a limit stores nothing for this entry and returns ErrDiskLimitReached; entries
// added before it remain usable. The first entry at a path wins.
func (r *Resolver) add(hdr tar.Header, content io.Reader) error {
	entryPath := path.Clean("/" + hdr.Name)
	if entryPath == "/" {
		return nil
	}

	// directories the path implies that do not exist yet are nodes this entry pays for
	var newDirs int64
	for i := 1; i < len(entryPath); i++ {
		if entryPath[i] == '/' {
			if _, ok := r.byPath[entryPath[:i]]; !ok {
				newDirs++
			}
		}
	}
	if !r.chargeIndex(approxIndexBytes(hdr) + newDirs*approxIndexBytesPerEntry) {
		return ErrDiskLimitReached
	}

	for i := 1; i < len(entryPath); i++ {
		if entryPath[i] == '/' {
			r.nodeAt(entryPath[:i], true)
		}
	}
	_, existed := r.byPath[entryPath]
	n := r.nodeAt(entryPath, hdr.FileInfo().IsDir())
	if n.header != nil {
		return nil
	}

	if hdr.Typeflag == tar.TypeReg && content != nil {
		// reading one byte past the cap is how an entry over it is told apart from one exactly at it
		err := r.put(&n.content, io.LimitReader(content, maxEntryBytes+1))
		if err == nil && n.content.size > maxEntryBytes {
			err = errEntryTooLarge
		}
		if err != nil {
			r.discard(&n.content)
			if !existed {
				delete(r.byPath, entryPath)
			}
			if errors.Is(err, errEntryTooLarge) {
				r.truncate(fmt.Sprintf("an entry larger than %s was skipped", humanize.IBytes(uint64(maxEntryBytes))))
				return nil
			}
			if !errors.Is(err, ErrDiskLimitReached) {
				return fmt.Errorf("unable to read archive entry %q: %w", hdr.Name, err)
			}
			return err
		}
	}

	n.header = &hdr
	n.metadata = r.metadataOf(n)
	if n.isDir {
		return nil
	}
	r.files = append(r.files, n)
	r.names.Update(path.Base(entryPath), func(current *syftindex.Node[[]*node]) []*node {
		return append(current.Value(), n)
	})
	return nil
}

// maxEntryBytes caps any one entry, as the legacy java extraction did (see intFile.SafeCopy): without it
// a single entry of an overlapping-entry zip bomb can decompress up to the disk limit.
var maxEntryBytes int64 = intFile.PerFileReadLimit

var errEntryTooLarge = errors.New("archive entry exceeds the per-entry size cap")

// truncate marks the resolver as covering part of the archive, keeping the first reason given.
func (r *Resolver) truncate(reason string) {
	if !r.Truncated {
		r.Truncated, r.TruncatedReason = true, reason
	}
}

// chargeIndex charges index bookkeeping, which lives in memory. Content held in memory can move to
// disk to make room for it; the index cannot, so when it is refused the entries are.
func (r *Resolver) chargeIndex(n int64) bool {
	if r.charge.index(n) {
		return true
	}
	if len(r.held) == 0 || r.spill() != nil {
		return false
	}
	return r.charge.index(n)
}

// nodeAt returns the node at a rooted path, creating it under its parent, which must exist already.
func (r *Resolver) nodeAt(p string, isDir bool) *node {
	if n, ok := r.byPath[p]; ok {
		return n
	}
	slash := strings.LastIndexByte(p, '/')
	parentPath := p[:slash]
	if parentPath == "" {
		parentPath = "/"
	}
	parent := r.byPath[parentPath]
	n := &node{path: p, name: p[slash+1:], isDir: isDir, parent: parent}
	parent.children = append(parent.children, n)
	r.byPath[p] = n
	if isDir {
		r.dirs.Update(n.name, func(current *syftindex.Node[[]*node]) []*node {
			return append(current.Value(), n)
		})
	}
	return n
}

// finish orders the files and resolves links once every entry is added.
func (r *Resolver) finish() {
	sort.Slice(r.files, func(i, j int) bool { return r.files[i].path < r.files[j].path })
	for _, n := range r.byPath {
		n.target = r.linkTarget(n)
	}
}

// maxLinkHops bounds a chain of links pointing at links, which is also what ends a cycle.
const maxLinkHops = 8

func (r *Resolver) linkTarget(n *node) *node {
	for hops := 0; hops <= maxLinkHops; hops++ {
		if n.header == nil || n.isDir {
			return nil
		}
		if n.header.Linkname == "" {
			return n
		}
		next, ok := r.byPath[linkDestination(n.path, n.header.Linkname, n.header.Typeflag == tar.TypeLink)]
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
func linkDestination(linkPath, linkname string, hard bool) string {
	if hard || path.IsAbs(linkname) {
		return path.Join("/", linkname)
	}
	return path.Join(path.Dir(linkPath), linkname)
}

func (r *Resolver) metadataOf(n *node) file.Metadata {
	metadata := stereoscopeFile.NewMetadata(*n.header, r.open(&n.content))
	// NewMetadata copies the header and points FileInfo into the copy; share the one the node holds
	metadata.FileInfo = n.header.FileInfo()
	metadata.Path = reportedPath(n.path)
	if n.header.Linkname != "" {
		metadata.LinkDestination = reportedPath(linkDestination(n.path, n.header.Linkname, n.header.Typeflag == tar.TypeLink))
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

func (r *Resolver) coordinates(n *node) file.Coordinates {
	return file.Coordinates{
		RealPath:     reportedPath(n.path),
		FileSystemID: r.fileSystemID,
		ArchivePath:  r.archivePath,
	}
}

// locationOf names a node by its own path.
func (r *Resolver) locationOf(n *node) file.Location {
	return file.NewLocationFromCoordinates(r.coordinates(n))
}

// resolvedLocation names the file behind a node: a link is reported at its target's path with the
// link's own path as the access path, and a link leading nowhere is reported as itself.
func (r *Resolver) resolvedLocation(n *node) file.Location {
	if n.target == nil || n.target == n {
		return r.locationOf(n)
	}
	return file.NewVirtualLocationFromCoordinates(r.coordinates(n.target), reportedPath(n.path))
}

func (r *Resolver) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	n, ok := r.byPath[rootedPath(location.RealPath)]
	if !ok || n.header == nil {
		return nil, fmt.Errorf("no archive entry for path=%q", location.RealPath)
	}
	return entryReader{r.open(&n.content)}, nil
}

func (r *Resolver) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	n, ok := r.byPath[rootedPath(location.RealPath)]
	if !ok {
		return file.Metadata{}, fmt.Errorf("no archive entry for path=%q", location.RealPath)
	}
	return n.metadata, nil
}

func (r *Resolver) HasPath(userPath string) bool {
	_, ok := r.byPath[rootedPath(userPath)]
	return ok
}

func (r *Resolver) FilesByPath(paths ...string) ([]file.Location, error) {
	var out []file.Location
	seen := map[*node]struct{}{}
	for _, userPath := range paths {
		n, ok := r.byPath[rootedPath(userPath)]
		if !ok || n.isDir || n.header == nil {
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

func (r *Resolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	matched := map[*node]struct{}{}
	for _, pattern := range patterns {
		for _, segments := range parseGlob(pattern) {
			candidates, exact := r.globCandidates(segments)
			for _, n := range candidates {
				if !exact {
					ok, err := matchNode(segments, n)
					if err != nil {
						return nil, fmt.Errorf("invalid glob %q: %w", pattern, err)
					}
					if !ok {
						continue
					}
				}
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

func (r *Resolver) FilesByMIMEType(types ...string) ([]file.Location, error) {
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
func (r *Resolver) RelativeFileByPath(_ file.Location, userPath string) *file.Location {
	locations, _ := r.FilesByPath(userPath)
	if len(locations) == 0 {
		return nil
	}
	return &locations[0]
}

func (r *Resolver) AllLocations(ctx context.Context) <-chan file.Location {
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

// entryReader gives an entry's reader the Close the resolver interface requires. The resolver owns
// the bytes, so there is nothing to close.
type entryReader struct {
	ReaderAtSeeker
}

func (entryReader) Close() error { return nil }

// maxEntryNameBytes is the longest entry name stored: PATH_MAX. Every path component becomes a node,
// so a longer name is a cheap way to inflate the index and no filesystem could hold it anyway.
const maxEntryNameBytes = 4096

// entryHeader builds the header stored for one archive entry, or reports false for an entry not worth
// carrying: device nodes, fifos and sockets, which no cataloger reads, and names that cannot be a path
// inside the archive.
//
// The name is cleaned to an archive-relative path with no leading slash, so "../x" names x at the
// archive root rather than anything outside it. Symlinks are stored as headers, never followed on the
// host; the resolver resolves their targets inside the archive.
func entryHeader(f archives.FileInfo) (tar.Header, bool) {
	mode := f.Mode()
	if !mode.IsRegular() && !mode.IsDir() && mode.Type()&fs.ModeSymlink == 0 {
		log.WithFields("entry", f.NameInArchive, "mode", mode).Debug("skipping non-regular archive entry")
		return tar.Header{}, false
	}

	name, ok := entryName(f.NameInArchive)
	if !ok {
		log.WithFields("entry-name-bytes", len(f.NameInArchive)).Trace("skipping archive entry with an unusable name")
		return tar.Header{}, false
	}

	hdr, err := tar.FileInfoHeader(f.FileInfo, f.LinkTarget)
	if err != nil {
		log.WithFields("entry", f.NameInArchive, "error", err).Debug("skipping archive entry with an unusable header")
		return tar.Header{}, false
	}
	hdr.Name = name
	hdr.Linkname = f.LinkTarget

	// nothing reads these, and the header is held for the life of the archive
	hdr.PAXRecords = nil
	hdr.Uname, hdr.Gname = "", ""
	hdr.AccessTime, hdr.ChangeTime = time.Time{}, time.Time{}
	hdr.ModTime = hdr.ModTime.Truncate(time.Second)

	return *hdr, true
}

// entryName cleans an archive entry's name to a path relative to the archive root, reporting false
// when it names nothing inside the archive.
func entryName(name string) (string, bool) {
	if len(name) > maxEntryNameBytes || strings.ContainsRune(name, 0) {
		return "", false
	}
	cleaned := strings.TrimPrefix(path.Clean("/"+name), "/")
	return cleaned, cleaned != ""
}
