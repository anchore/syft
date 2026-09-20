package fileresolver

import (
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/internal/log"
)

// overflowEntryReader is a reader over one entry of an archive's store. Its marker method lets the
// archive cataloger recognize a nested archive as already-random-access, already-charged content,
// without either package importing the other.
type overflowEntryReader struct {
	entryReadCloser
}

// OverflowArchiveEntry marks this reader as content that needs no copy to be read at random.
func (overflowEntryReader) OverflowArchiveEntry() {}

// entryReadCloser is a bounded view onto the bytes the store holds for one entry.
type entryReadCloser interface {
	io.ReadCloser
	io.ReaderAt
	io.Seeker
}

// archiveRoot is the root handed to a path filter. Archive entries are relative to the archive, which
// has no host location, so the root is the archive itself.
const archiveRoot = "/"

type filterOutcome int

const (
	keepEntry filterOutcome = iota
	skipEntry
	skipTree
)

// runPathFilters asks each filter about one entry, mapping a walk's answers (skip path, skip dir)
// onto an unordered pass over archive entries.
//
// entryPath is archive-relative and the root is the archive's own root, not a host path: the archive
// is indexed in memory, and matching against the host temp path could match segments the archive's
// contents never carry.
func runPathFilters(filters []PathIndexVisitor, entryPath string, info os.FileInfo) filterOutcome {
	for _, filter := range filters {
		if filter == nil {
			continue
		}
		switch err := filter(archiveRoot, entryPath, info, nil); err {
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

// isPruned reports whether an entry sits inside an already-pruned directory. An archive is a
// sequence, not a walk, so SkipDir cannot end a subtree; each later entry is checked instead.
func isPruned(entryPath string, pruned []string) bool {
	for _, dir := range pruned {
		if entryPath == dir || strings.HasPrefix(entryPath, dir+"/") {
			return true
		}
	}
	return false
}

// maxEntryPathBytes is the longest entry path this package will index: PATH_MAX.
//
// Each path component becomes a tree node, so a long name like "a/a/.../a/f" expands a few hundred
// compressed bytes into a huge directory chain (a 352-byte tar.gz produced 200,000 nodes and 44 MB of
// index). This caps the per-entry cost; the index's per-node charge caps how many such entries a scan
// admits.
//
// A longer path is one no filesystem could hold, so refusing it drops nothing a real extraction or
// directory scan would have found. Go's tar reader alone allows names far longer.
const maxEntryPathBytes = 4096

// sanitizeEntryName converts an archive entry's name into a path inside that archive, reporting false
// when the name is empty or too long to be a path.
//
// Nothing is written through the name; this guards the path the SBOM reports. Cleaning against the
// root clamps "../" climbs, so an attacker-supplied name yields at worst a wrong path inside the right
// archive, never a claim about the host filesystem.
func sanitizeEntryName(name string) (string, bool) {
	if strings.ContainsRune(name, 0) {
		return "", false
	}
	if len(name) > maxEntryPathBytes {
		// tested before cleaning: cleaning only shortens, and building the cleaned copy of a
		// multi-megabyte name is itself part of what this refuses
		log.WithFields("entry-name-bytes", len(name)).
			Trace("skipping archive entry whose name is longer than any path a filesystem could hold")
		return "", false
	}
	cleaned := strings.TrimPrefix(path.Clean("/"+name), "/")
	if cleaned == "" || cleaned == "." {
		// the archive's own root, which is not an entry in it
		return "", false
	}
	return cleaned, true
}
