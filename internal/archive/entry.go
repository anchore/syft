package archive

import (
	"archive/tar"
	"io/fs"
	"path"
	"strings"
	"time"

	"github.com/mholt/archives"

	"github.com/anchore/syft/internal/log"
)

// Entry is one archive entry: its header and where its content is. Content starts in memory and
// moves to the store's overflow file when memory runs out; the move changes nothing an index over
// the entry holds.
type Entry struct {
	Header tar.Header

	mem    []byte // content while held in memory
	offset int64  // where content starts in the overflow file once written there
	size   int64
}

// maxEntryNameBytes is the longest entry name stored: PATH_MAX. Every path component becomes an index
// node, so a longer name is a cheap way to inflate the index and no filesystem could hold it anyway.
const maxEntryNameBytes = 4096

// entryHeader builds the header stored for one archive entry, or reports false for an entry not worth
// carrying: device nodes, fifos and sockets, which no cataloger reads, and names that cannot be a path
// inside the archive.
//
// The name is cleaned to an archive-relative path with no leading slash, so "../x" names x at the
// archive root rather than anything outside it. Symlinks are stored as headers, never followed on the
// host; the index resolves their targets inside the archive.
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
