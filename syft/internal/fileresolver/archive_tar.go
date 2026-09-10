package fileresolver

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/windows"
)

var _ file.Resolver = (*ArchiveTar)(nil)

// ArchiveTar implements path and content access for one archive whose entries were overflowed into a
// single tar.
//
// It is the same FiletreeResolver a directory scan uses, differing only in where the tree comes from
// and how content is opened. That separation already existed: FiletreeResolver holds Tree, Index and
// an Opener, and nativeOSFileOpener - which opens a path on the real filesystem - is one
// implementation of that Opener among several. Reading an entry out of a tar by seek offset is
// another, so no resolver interface changes to accommodate it.
//
// Paths are reported relative to the archive's own root, exactly as they were when the archive was
// expanded into a directory: the tree is rooted at an empty directory standing in for the archive
// root, and the chroot context relativizes against it. Nothing about the storage - the tar, its
// offsets, the scratch directory holding it - is reachable from a Location.
type ArchiveTar struct {
	FiletreeResolver
	tarPath string

	// records is how many entries of the tar were indexed.
	records int

	// truncated reports that indexing stopped before the end of the tar.
	truncated bool
}

// NewFromArchiveTar builds a resolver over the archive entries held in the tar at tarPath, whose
// Locations are reported relative to rootDir and stamped with fileSystemID and archivePath.
//
// rootDir must exist and is expected to be empty: it is the archive's logical root and nothing is
// ever written into it. Every entry the tar holds is indexed: what bounds a crafted archive is the
// disk limit charged as its entries were written, which is the resource the entries actually consume.
//
// pathFilters are applied to each entry the way they are applied to each path of a directory walk, so
// an exclusion pattern reaches inside an archive by exactly the mechanism it did before: the entry it
// matches is absent from the archive's filesystem rather than present and skipped.
func NewFromArchiveTar(rootDir, tarPath, fileSystemID, archivePath string, pathFilters ...PathIndexVisitor) (*ArchiveTar, error) {
	chroot, err := NewChrootContextFromCWD(rootDir, "")
	if err != nil {
		return nil, fmt.Errorf("unable to interpret chroot context for archive root %q: %w", rootDir, err)
	}

	r := &ArchiveTar{
		tarPath: tarPath,
		FiletreeResolver: FiletreeResolver{
			Chroot:       *chroot,
			FileSystemID: fileSystemID,
			ArchivePath:  archivePath,
		},
	}

	if err := r.buildIndex(chroot.Root(), pathFilters); err != nil {
		return nil, err
	}

	return r, nil
}

// Records is how many entries this archive's filesystem holds.
func (r *ArchiveTar) Records() int {
	return r.records
}

// IndexTruncated reports that indexing stopped before the end of the tar, so the filesystem holds
// only part of what the archive contained. It is not an error: what was indexed is complete and
// usable, there is simply less of it.
func (r *ArchiveTar) IndexTruncated() bool {
	return r.truncated
}

func (r *ArchiveTar) String() string {
	return fmt.Sprintf("archive:%s", r.tarPath)
}

// buildIndex walks the overflow tar once, adding a node to the filetree and a record to the index for
// each entry, and keeping the entry itself so content can later be opened at its offset.
//
// A visitor error is never fatal to the archive. A crafted tar can hold two entries whose names
// disagree about what kind of node a path is, and letting that cost the whole archive would hand an
// attacker a way to hide everything else in it.
func (r *ArchiveTar) buildIndex(root string, pathFilters []PathIndexVisitor) error {
	tree := filetree.New()
	index := filetree.NewIndex()
	builder := filetree.NewBuilder(tree, index)
	entries := make(map[stereoscopeFile.ID]stereoscopeFile.TarIndexEntry)

	rootPath := treeRoot(root)
	var pruned []string

	add := func(entry stereoscopeFile.TarIndexEntry) {
		if ref, ok := r.addEntry(builder, entry, root, rootPath, pathFilters, &pruned); ok {
			entries[ref] = entry
			r.records++
		}
	}

	// One entry behind: an entry is added only once the header after it has been read, so an entry
	// whose data the tar stops part way through is never in the filesystem. It matters because a tar
	// CAN end mid-entry - that is what the disk limit refusing a chunk of a copy leaves behind - and a
	// half-present jar or pom that a cataloger parses anyway is worse than an absent one. The lag is
	// what makes "the entries before the cut" mean the entries whose content is all there.
	var pending *stereoscopeFile.TarIndexEntry

	visitor := func(entry stereoscopeFile.TarIndexEntry) error {
		if pending != nil {
			add(*pending)
			pending = nil
		}
		pending = &entry
		return nil
	}

	if _, err := stereoscopeFile.NewTarIndex(r.tarPath, visitor); err != nil {
		if r.records == 0 {
			return fmt.Errorf("unable to index archive contents %q: %w", r.tarPath, err)
		}
		// the tar ends part way through an entry. Everything complete before that point is intact, so
		// it is kept and reported as a truncation rather than discarding an archive that was cataloged
		// perfectly well up to the cut.
		log.WithFields("archive", r.tarPath, "error", err).
			Debug("archive contents end part way through an entry; cataloging what was read")
		r.truncated = true
	} else if pending != nil {
		// the tar ended cleanly, so the last entry read is whole
		add(*pending)
	}

	r.Tree = tree
	r.Index = index
	r.SearchContext = filetree.NewSearchContext(tree, index)
	r.Opener = tarEntryOpener(entries)

	return nil
}

// addEntry puts one tar entry into the filetree and the index, reporting the reference it was given,
// or false when the entry is not part of this archive's filesystem: a name that names nothing, a path
// under a directory a filter pruned, a path a filter excluded, or a path a crafted archive has
// already claimed as a different kind of node.
func (r *ArchiveTar) addEntry(builder *filetree.Builder, entry stereoscopeFile.TarIndexEntry, root, rootPath string, pathFilters []PathIndexVisitor, pruned *[]string) (stereoscopeFile.ID, bool) {
	hdr := entry.ToTarFileEntry().Header

	name, ok := sanitizeEntryName(hdr.Name)
	if !ok {
		return 0, false
	}
	entryPath := path.Join(rootPath, name)

	if isPruned(entryPath, *pruned) {
		return 0, false
	}

	switch runPathFilters(pathFilters, root, entryPath, hdr.FileInfo()) {
	case skipEntry:
		return 0, false
	case skipTree:
		*pruned = append(*pruned, entryPath)
		return 0, false
	}

	ref, err := builder.Add(entryMetadata(entry, hdr, rootPath, entryPath))
	if err != nil {
		log.WithFields("entry", hdr.Name, "error", err).
			Trace("unable to add archive entry to its filesystem, skipping it")
		return 0, false
	}
	return ref.ID(), true
}

// entryMetadata describes one tar entry as a file in the archive's filesystem.
//
// The path and the link destination are both rewritten into the archive's own root. A link is
// resolved in archive-relative space first, where path.Join clamps a climb at the root, so a target
// naming the host filesystem - "/etc/passwd", or a chain of ".." - lands somewhere inside this
// archive or nowhere at all. That is stronger than the check it replaces: the previous code refused
// to create such a link, and here there is nothing to create in the first place.
func entryMetadata(entry stereoscopeFile.TarIndexEntry, hdr tar.Header, rootPath, entryPath string) file.Metadata {
	contents := entry.Open()
	metadata := stereoscopeFile.NewMetadata(hdr, contents)
	if err := contents.Close(); err != nil {
		log.WithFields("entry", hdr.Name, "error", err).Trace("unable to close archive entry after reading its type")
	}

	metadata.Path = entryPath

	if hdr.Linkname != "" {
		relative := path.Clean(hdr.Linkname)
		if !path.IsAbs(relative) {
			relative = path.Join("/", path.Dir(strings.TrimPrefix(entryPath, rootPath)), hdr.Linkname)
		}
		metadata.LinkDestination = path.Join(rootPath, relative)
	}

	return metadata
}

// tarEntryOpener opens an entry's content by seeking to its offset in the tar.
//
// The reader is bounded to the entry, and it is Read, Seek and ReadAt - so reading the last entry of
// a large archive costs a seek rather than a pass over everything before it, and a nested archive can
// be handed straight to an archive format that needs random access instead of being copied out first.
func tarEntryOpener(entries map[stereoscopeFile.ID]stereoscopeFile.TarIndexEntry) func(stereoscopeFile.Reference) (io.ReadCloser, error) {
	return func(ref stereoscopeFile.Reference) (io.ReadCloser, error) {
		entry, ok := entries[ref.ID()]
		if !ok {
			return nil, fmt.Errorf("no archive entry for path=%q", ref.RealPath)
		}
		contents := entry.Open()
		seekable, ok := contents.(entryReadCloser)
		if !ok {
			// still readable, just not readable at an offset: whatever wants random access will copy
			// it out first, which is what happened to every nested archive before this
			return contents, nil
		}
		return overflowEntryReader{seekable}, nil
	}
}

// overflowEntryReader is a reader over one entry of an archive's overflow tar.
//
// The marker method is what lets the archive cataloger recognize a nested archive as content it can
// read where it lies - already random access, already charged to the archive holding it - without
// either package importing the other.
type overflowEntryReader struct {
	entryReadCloser
}

// OverflowArchiveEntry marks this reader as content that needs no copy to be read at random.
func (overflowEntryReader) OverflowArchiveEntry() {}

// entryReadCloser is what a tar index entry hands back: a read closer that also seeks and reads at an
// offset, because it is a bounded view onto the tar file.
type entryReadCloser interface {
	io.ReadCloser
	io.ReaderAt
	io.Seeker
}

type filterOutcome int

const (
	keepEntry filterOutcome = iota
	skipEntry
	skipTree
)

// runPathFilters asks each filter about one entry, translating the answers a directory walk uses -
// skip this path, skip this whole directory - into what an unordered pass over tar entries can act on.
func runPathFilters(filters []PathIndexVisitor, root, entryPath string, info os.FileInfo) filterOutcome {
	for _, filter := range filters {
		if filter == nil {
			continue
		}
		switch err := filter(root, entryPath, info, nil); err {
		case nil:
			continue
		case filepath.SkipDir, filepath.SkipAll:
			return skipTree
		default:
			return skipEntry
		}
	}
	return keepEntry
}

// isPruned reports whether an entry sits inside a directory a filter already pruned. A tar is a
// sequence, not a walk, so a pruned directory cannot simply end a subtree the way returning SkipDir
// from a walk does: each later entry is checked against what was pruned.
func isPruned(entryPath string, pruned []string) bool {
	for _, dir := range pruned {
		if entryPath == dir || strings.HasPrefix(entryPath, dir+"/") {
			return true
		}
	}
	return false
}

// sanitizeEntryName turns the name an archive gave an entry into a path inside that archive, and
// reports false for a name that names nothing.
//
// Nothing is written through an entry's name any more - it is a field in a tar header - so this is
// not about arbitrary writes. It is about the path the SBOM reports: a name like "../../etc/passwd"
// left alone would put a node above the archive's own root, which renders as a path outside the
// archive and reads as a claim about the host filesystem. Cleaning it against the root clamps the
// climb, so the worst an attacker-controlled name produces is a wrong path inside the right archive.
func sanitizeEntryName(name string) (string, bool) {
	if strings.ContainsRune(name, 0) {
		return "", false
	}
	cleaned := strings.TrimPrefix(path.Clean("/"+name), "/")
	if cleaned == "" || cleaned == "." {
		// the archive's own root, which is not an entry in it
		return "", false
	}
	return cleaned, true
}

// treeRoot is the archive root as a filetree path: posix, absolute, and on Windows with the volume
// encoded the way every other resolver encodes it.
func treeRoot(root string) string {
	if windows.HostRunningOnWindows() {
		return windows.ToPosix(root)
	}
	return path.Clean(filepath.ToSlash(root))
}
