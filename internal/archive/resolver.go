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
	"github.com/anchore/stereoscope/pkg/filetree"
	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/tmpdir"
	"github.com/anchore/syft/syft/file"
)

// Resolver is one archive opened as its own filesystem: a file.Resolver over the entries Extract fed
// into it, holding their content within the scan's limits. Entries are indexed in a stereoscope file
// tree, the same index the directory and image resolvers search.
//
// Locations it returns keep the outermost archive's RealPath and carry the entry's FullPath. Queries
// may name an entry either by its full path or by its path within the archive (see rootedPath).
type Resolver struct {
	// Digests are of the archive file itself.
	Digests []file.Digest

	// Truncated is non-nil when the resolver covers only part of the archive, and says why: the disk limit
	// or the decompression budget stopped extraction early, or an entry was too large or unreadable.
	Truncated error

	archiveCoordinates file.Coordinates
	charge             *charge
	budget             *Budget

	// content is held in memory while the memory limit admits it and in one spill file once it does
	// not. The file is created on first use, so an archive that stays in memory never touches the
	// filesystem, and blobs are located in it by offset with no framing of their own.
	tempDir *tmpdir.TempDir
	held    []*blob // blobs in memory, in the order they were added
	file    *os.File
	remove  func()
	written int64
	chunk   []byte

	tree    *filetree.FileTree
	index   filetree.Index
	search  filetree.Searcher // built by finish, once every entry is in the tree
	content map[stereoscopeFile.ID]*blob
	entries int // non-directory entries added
}

var _ file.Resolver = (*Resolver)(nil)

// newResolver returns an empty resolver whose locations extend the archive's coordinates, spilling into
// the scan's temp root when ctx carries one (see internal/tmpdir).
func newResolver(ctx context.Context, archiveCoordinates file.Coordinates, charge *charge) *Resolver {
	return &Resolver{
		archiveCoordinates: archiveCoordinates,
		charge:             charge,
		budget:             budgetFromContext(ctx),
		tempDir:            tmpdir.FromContext(ctx),
		tree:               filetree.New(),
		index:              filetree.NewIndex(),
		content:            map[stereoscopeFile.ID]*blob{},
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

// approxIndexBytesPerEntry estimates what holding one tree node costs beyond its content: the node, its
// header and metadata, and its index slots. It is charged for every node an entry creates, including
// the directories its path implies, so an archive of many tiny entries or of a few entries with very
// deep paths is still bounded by the limits.
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
	if exists, res, _ := r.tree.File(stereoscopeFile.Path(entryPath)); exists && res.HasReference() {
		return nil
	}

	// directories the path implies that do not exist yet are nodes this entry pays for
	var newDirs []string
	for i := 1; i < len(entryPath); i++ {
		if entryPath[i] == '/' && !r.tree.HasPath(stereoscopeFile.Path(entryPath[:i])) {
			newDirs = append(newDirs, entryPath[:i])
		}
	}
	if !r.chargeIndex(approxIndexBytes(hdr) + int64(len(newDirs))*approxIndexBytesPerEntry) {
		return ErrDiskLimitReached
	}
	// indexed as if listed, since a search for a directory's children looks the directory up by name
	for _, dir := range newDirs {
		if err := r.store(dir, tar.Header{Name: dir, Typeflag: tar.TypeDir, Mode: 0o755}, &blob{}); err != nil {
			log.WithFields("entry", hdr.Name, "error", err).Trace("skipping archive entry")
			return nil
		}
	}

	b := &blob{}
	if hdr.Typeflag == tar.TypeReg && content != nil {
		// reading one byte past the cap is how an entry over it is told apart from one exactly at it
		err := r.put(b, io.LimitReader(content, maxEntryBytes+1))
		if err == nil && b.size > maxEntryBytes {
			err = errEntryTooLarge
		}
		if err != nil {
			r.discard(b)
			if errors.Is(err, errEntryTooLarge) {
				r.truncate(fmt.Errorf("an entry was skipped: %w of %s", err, humanize.IBytes(uint64(maxEntryBytes))))
				return nil
			}
			if errors.Is(err, ErrDiskLimitReached) || errors.Is(err, errBudgetSpent) {
				return err
			}
			// a damaged entry (a CRC mismatch, a corrupt deflate stream) costs only that entry
			r.truncate(fmt.Errorf("entry %q could not be read: %w", hdr.Name, err))
			return nil
		}
	}

	if err := r.store(entryPath, hdr, b); err != nil {
		// a path the tree cannot hold, such as a file beneath another file's name
		r.discard(b)
		log.WithFields("entry", hdr.Name, "error", err).Trace("skipping archive entry")
		return nil
	}
	if hdr.Typeflag != tar.TypeDir {
		r.entries++
	}
	return nil
}

func (r *Resolver) store(rooted string, hdr tar.Header, b *blob) error {
	ref, err := r.addToTree(rooted, hdr)
	if err != nil {
		return err
	}
	metadata := stereoscopeFile.NewMetadata(hdr, r.open(b))
	metadata.Path = entryPath(rooted)
	r.index.Add(*ref, metadata)
	r.content[ref.ID()] = b
	return nil
}

func (r *Resolver) addToTree(entryPath string, hdr tar.Header) (*stereoscopeFile.Reference, error) {
	p := stereoscopeFile.Path(entryPath)
	switch hdr.Typeflag {
	case tar.TypeDir:
		return r.tree.AddDir(p)
	case tar.TypeSymlink:
		return r.tree.AddSymLink(p, stereoscopeFile.Path(hdr.Linkname))
	case tar.TypeLink:
		// a hard link names its target from the archive root
		return r.tree.AddHardLink(p, stereoscopeFile.Path(path.Join("/", hdr.Linkname)))
	default:
		return r.tree.AddFile(p)
	}
}

// maxEntryBytes caps any one entry, as the legacy java extraction did (see intFile.SafeCopy): without it
// a single entry of an overlapping-entry zip bomb can decompress up to the disk limit.
var maxEntryBytes int64 = intFile.PerFileReadLimit

var errEntryTooLarge = errors.New("archive entry exceeds the per-entry size cap")

// truncate marks the resolver as covering part of the archive, keeping the first reason given.
func (r *Resolver) truncate(err error) {
	if r.Truncated == nil {
		r.Truncated = err
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

// finish builds the search context once every entry is added.
func (r *Resolver) finish() {
	r.search = filetree.NewSearchContext(r.tree, r.index)
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

// entryPath is a node's path within the archive: archive-relative with no leading slash.
func entryPath(rooted string) string {
	return strings.TrimPrefix(rooted, "/")
}

// fullPath is how paths leave the resolver: the archive's own full path, then the entry path.
func (r *Resolver) fullPath(rooted string) string {
	return r.archiveCoordinates.FullNestedPath() + "!/" + entryPath(rooted)
}

// rootedPath is the tree path a query names, which is either form a path takes: a full path is trimmed to
// the entry path within this archive, and anything else (a LocalPath) is taken as archive-relative
// already. The archive's full path with a trailing "!" (what path.Dir gives for an entry at the root)
// names the root.
func (r *Resolver) rootedPath(userPath string) string {
	archivePath := r.archiveCoordinates.FullNestedPath() + "!"
	if userPath == archivePath {
		return "/"
	}
	return path.Clean("/" + strings.TrimPrefix(userPath, archivePath+"/"))
}

// coordinates name an entry by the outermost archive's real path, which never includes a path inside an
// archive, and its full path through every archive.
func (r *Resolver) coordinates(rooted string) file.Coordinates {
	return file.Coordinates{
		RealPath:     r.archiveCoordinates.RealPath,
		FileSystemID: r.archiveCoordinates.FileSystemID,
		FullPath:     r.fullPath(rooted),
	}
}

// location names a resolution: a link is reported at its target's path with the link's own full path
// as the access path.
func (r *Resolver) location(res stereoscopeFile.Resolution) file.Location {
	coordinates := r.coordinates(string(res.RealPath))
	if res.RequestPath == "" || res.RequestPath == res.RealPath {
		return file.NewLocationFromCoordinates(coordinates)
	}
	return file.NewVirtualLocationFromCoordinates(coordinates, r.fullPath(string(res.RequestPath)))
}

// resolve finds the file a path names, following links, and reports false for directories and
// paths the archive never listed.
func (r *Resolver) resolve(userPath string) (*stereoscopeFile.Resolution, bool) {
	res, err := r.search.SearchByPath(r.rootedPath(userPath), filetree.FollowBasenameLinks)
	if err != nil || res == nil || !res.HasReference() {
		return nil, false
	}
	entry, err := r.index.Get(*res.Reference)
	if err != nil || entry.IsDir() {
		return nil, false
	}
	return res, true
}

func (r *Resolver) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	res, ok := r.resolve(location.FullNestedPath())
	if !ok {
		return nil, fmt.Errorf("no archive entry for path=%q", location.FullNestedPath())
	}
	return entryReader{r.open(r.content[res.ID()])}, nil
}

func (r *Resolver) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	rooted := r.rootedPath(location.FullNestedPath())
	exists, res, err := r.tree.File(stereoscopeFile.Path(rooted))
	if err != nil || !exists || !res.HasReference() {
		return file.Metadata{}, fmt.Errorf("no archive entry for path=%q", location.FullNestedPath())
	}
	entry, err := r.index.Get(*res.Reference)
	if err != nil {
		return file.Metadata{}, err
	}
	// the index holds entry paths; callers get full paths, as with locations
	metadata := entry.Metadata
	metadata.Path = r.fullPath(rooted)
	if metadata.LinkDestination != "" {
		metadata.LinkDestination = r.fullPath(linkDestination(rooted, metadata.LinkDestination, metadata.Type == stereoscopeFile.TypeHardLink))
	}
	return metadata, nil
}

func (r *Resolver) HasPath(userPath string) bool {
	return r.tree.HasPath(stereoscopeFile.Path(r.rootedPath(userPath)))
}

func (r *Resolver) FilesByPath(paths ...string) ([]file.Location, error) {
	var out []file.Location
	seen := stereoscopeFile.NewFileReferenceSet()
	for _, userPath := range paths {
		res, ok := r.resolve(userPath)
		if !ok || seen.Contains(*res.Reference) {
			continue
		}
		seen.Add(*res.Reference)
		out = append(out, r.location(*res))
	}
	return out, nil
}

func (r *Resolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	var out []file.Location
	seen := stereoscopeFile.NewFileReferenceSet()
	for _, pattern := range patterns {
		results, err := r.searchByGlob(r.rootedPath(pattern))
		if err != nil {
			return nil, fmt.Errorf("invalid glob %q: %w", pattern, err)
		}
		for _, res := range results {
			if !res.HasReference() || seen.Contains(*res.Reference) {
				continue
			}
			entry, err := r.index.Get(*res.Reference)
			if err != nil || entry.IsDir() {
				continue
			}
			seen.Add(*res.Reference)
			out = append(out, r.location(res))
		}
	}
	sortLocations(out)
	return out, nil
}

// searchByGlob is the index search, except that stereoscope answers "<dir>/*" by looking the directory
// up by name and the root has none, so "/*" walks the tree instead.
func (r *Resolver) searchByGlob(pattern string) ([]stereoscopeFile.Resolution, error) {
	if pattern == "/*" {
		return r.tree.FilesByGlob(pattern, filetree.FollowBasenameLinks)
	}
	return r.search.SearchByGlob(pattern, filetree.FollowBasenameLinks)
}

// sortLocations orders answers by path, which decides how locations group into packages when results
// merge into the SBOM.
func sortLocations(locations []file.Location) {
	sort.Slice(locations, func(i, j int) bool {
		if a, b := locations[i].FullNestedPath(), locations[j].FullNestedPath(); a != b {
			return a < b
		}
		return locations[i].AccessPath < locations[j].AccessPath
	})
}

func (r *Resolver) FilesByMIMEType(types ...string) ([]file.Location, error) {
	results, err := r.search.SearchByMIMEType(types...)
	if err != nil {
		return nil, err
	}
	var out []file.Location
	for _, res := range results {
		if res.HasReference() {
			out = append(out, r.location(res))
		}
	}
	sortLocations(out)
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
		refs := r.tree.AllFiles(stereoscopeFile.TypeRegular, stereoscopeFile.TypeSymLink, stereoscopeFile.TypeHardLink)
		sort.Slice(refs, func(i, j int) bool { return refs[i].RealPath < refs[j].RealPath })
		for _, ref := range refs {
			select {
			case out <- r.location(stereoscopeFile.Resolution{RequestPath: ref.RealPath, Reference: &ref}):
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
