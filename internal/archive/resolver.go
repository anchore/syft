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
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

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
	metered            bool // the budget is charged as the archive is decoded (see meteredReader), not in put

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
// added before it remain usable. The last entry at a path wins, as it does when the archive is
// extracted (tar appends updates, an OCI layer applies in order, and java's legacy zip reading
// overwrites too), so a stale earlier copy, such as an older pom.properties, can't stand in for what is
// really there.
func (r *Resolver) add(hdr tar.Header, content io.Reader) error {
	entryPath := path.Clean("/" + hdr.Name)
	if entryPath == "/" {
		return nil
	}
	replacing, ok := r.replace(entryPath, hdr)
	if !ok {
		return nil
	}

	// directories the path implies that do not exist yet are nodes this entry pays for. Walking from the
	// deepest parent up stops at the first that exists, since its ancestors exist too
	var newDirs []string
	for i := strings.LastIndexByte(entryPath, '/'); i > 0; i = strings.LastIndexByte(entryPath[:i], '/') {
		if r.tree.HasPath(stereoscopeFile.Path(entryPath[:i])) {
			break
		}
		newDirs = append(newDirs, entryPath[:i])
	}
	slices.Reverse(newDirs)
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
	if hdr.Typeflag != tar.TypeDir && !replacing {
		r.entries++
	}
	return nil
}

// replace clears the way for an entry at a path that is already held, reporting whether it did and
// false when the entry should be dropped. A later non-directory entry replaces an earlier one, refunding
// what it held. A file and a directory at one path keep the first, since swapping kinds would mean
// re-parenting what is already beneath it.
func (r *Resolver) replace(entryPath string, hdr tar.Header) (replacing, ok bool) {
	exists, res, _ := r.tree.File(stereoscopeFile.Path(entryPath))
	if !exists || !res.HasReference() {
		return false, true
	}
	earlier, err := r.index.Get(*res.Reference)
	if err != nil || earlier.IsDir() || hdr.Typeflag == tar.TypeDir {
		return false, false
	}
	// a removed node's index entry is left behind, but searches only answer with references in the tree
	if err := r.tree.RemovePath(stereoscopeFile.Path(entryPath)); err != nil {
		log.WithFields("entry", hdr.Name, "error", err).Trace("unable to replace archive entry")
		return false, false
	}
	if b := r.content[res.ID()]; b != nil {
		r.discard(b)
	}
	delete(r.content, res.ID())
	return true, true
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
	return r.archiveCoordinates.FullNestedPath() + file.ArchivePathSeparator + entryPath(rooted)
}

// rootedPath is the tree path a query names, which is either form a path takes: a full path is trimmed to
// the entry path within this archive, and anything else (a LocalPath, with or without its leading slash)
// is taken as archive-relative already, since the tree looks a relative path up from its root. The archive's full path with a trailing "!" (what path.Dir gives for an entry at the root)
// names the root. A full path into another archive in the scan names nothing here and reports false.
func (r *Resolver) rootedPath(userPath string) (string, bool) {
	if rest, ok := strings.CutPrefix(userPath, r.archiveCoordinates.FullNestedPath()); ok {
		if rest == file.ArchivePathSeparator[:1] {
			return "/", true
		}
		if strings.HasPrefix(rest, file.ArchivePathSeparator) {
			// keep the separator's slash as the rooted path's
			return path.Clean(rest[len(file.ArchivePathSeparator)-1:]), true
		}
	}
	if r.outside(userPath) {
		return "", false
	}
	return path.Clean(userPath), true
}

// outside reports whether a path not under this archive's full path is a full path from the scan
// nonetheless: every full path in this archive tree starts with the outermost archive's real path and a
// separator. The real path alone is taken as an entry path, so an entry named like the outermost archive
// is found by its LocalPath.
func (r *Resolver) outside(userPath string) bool {
	rest, ok := strings.CutPrefix(userPath, r.archiveCoordinates.RealPath)
	return ok && strings.HasPrefix(rest, file.ArchivePathSeparator)
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
	rooted, ok := r.rootedPath(userPath)
	if !ok {
		return nil, false
	}
	res, err := r.search.SearchByPath(rooted, filetree.FollowBasenameLinks)
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
	rooted, ok := r.rootedPath(location.FullNestedPath())
	if !ok {
		return file.Metadata{}, fmt.Errorf("no archive entry for path=%q", location.FullNestedPath())
	}
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
	rooted, ok := r.rootedPath(userPath)
	return ok && r.tree.HasPath(stereoscopeFile.Path(rooted))
}

func (r *Resolver) FilesByPath(paths ...string) ([]file.Location, error) {
	var out []file.Location
	var seen []stereoscopeFile.ID // few paths are asked for at once
	for _, userPath := range paths {
		res, ok := r.resolve(userPath)
		if !ok || slices.Contains(seen, res.ID()) {
			continue
		}
		seen = append(seen, res.ID())
		out = append(out, r.location(*res))
	}
	return out, nil
}

func (r *Resolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	var out []file.Location
	seen := stereoscopeFile.NewFileReferenceSet()
	for _, pattern := range patterns {
		rooted, ok := r.rootedPath(pattern)
		if !ok {
			continue
		}
		results, err := r.searchByGlob(rooted)
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
// up by name and the root has none, so "/*" (or "*") walks the tree instead.
func (r *Resolver) searchByGlob(pattern string) ([]stereoscopeFile.Resolution, error) {
	if strings.TrimPrefix(pattern, "/") == "*" {
		return r.tree.FilesByGlob("/*", filetree.FollowBasenameLinks)
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

// RelativeFileByPath resolves against the archive root: an archive has no layers to be relative to.
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

// maxEntryNameDepth is the most path components an entry name may have. Adding an entry costs work per
// component, and no real archive nests anywhere near this deep.
const maxEntryNameDepth = 256

// entryHeader builds the header stored for one archive entry, or reports false for an entry not worth
// carrying: device nodes, fifos and sockets, which no cataloger reads, and names that cannot be a path
// inside the archive. A name refused as unsafe marks the resolver truncated.
//
// The name is cleaned to an archive-relative path with no leading slash, so "../x" names x at the
// archive root rather than anything outside it. Symlinks are stored as headers, never followed on the
// host; the resolver resolves their targets inside the archive.
func (r *Resolver) entryHeader(f archives.FileInfo) (tar.Header, bool) {
	mode := f.Mode()
	if !mode.IsRegular() && !mode.IsDir() && mode.Type()&fs.ModeSymlink == 0 {
		log.WithFields("entry", f.NameInArchive, "mode", mode).Debug("skipping non-regular archive entry")
		return tar.Header{}, false
	}

	name, err := entryName(f.NameInArchive)
	if err != nil {
		r.truncate(fmt.Errorf("an entry was skipped: %w", err))
		return tar.Header{}, false
	}
	if name == "" {
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

// entryName cleans an archive entry's name to a path relative to the archive root, returning "" when it
// names nothing inside the archive. This is the trust boundary for names: every one ends up in FullPath
// and the encoders, so a name that could forge an archive boundary ("!/") or a line in a line-oriented
// format (control characters, unicode line separators) is refused.
func entryName(name string) (string, error) {
	if len(name) > maxEntryNameBytes {
		return "", fmt.Errorf("entry name of %d bytes exceeds the %d byte cap", len(name), maxEntryNameBytes)
	}
	if strings.IndexFunc(name, isUnsafeNameRune) >= 0 {
		return "", fmt.Errorf("entry name %q contains a control character", name)
	}
	cleaned := strings.TrimPrefix(path.Clean("/"+name), "/")
	if depth := strings.Count(cleaned, "/") + 1; depth > maxEntryNameDepth {
		return "", fmt.Errorf("entry name of %d path components exceeds the %d component cap", depth, maxEntryNameDepth)
	}
	if strings.Contains(cleaned, file.ArchivePathSeparator) {
		return "", fmt.Errorf("entry name %q contains the archive path separator %q", name, file.ArchivePathSeparator)
	}
	return cleaned, nil
}

func isUnsafeNameRune(c rune) bool {
	return unicode.IsControl(c) || c == '\u2028' || c == '\u2029'
}
