package archive

import (
	"archive/tar"
	"io/fs"
	"strings"
	"time"

	"github.com/mholt/archives"

	"github.com/anchore/syft/internal/log"
)

// entryHeader builds the tar header for one archive entry's metadata, or reports false when the entry
// is not worth carrying. The entry's bytes are held separately.
//
// Symlinks are recorded as headers, not real links; the target is resolved later inside the archive's
// own filetree, so one naming the host filesystem resolves to nothing. Device nodes, fifos and
// sockets are skipped - no cataloger reads them.
func entryHeader(f archives.FileInfo) (*tar.Header, bool) {
	mode := f.Mode()
	if !mode.IsRegular() && !mode.IsDir() && mode.Type()&fs.ModeSymlink == 0 {
		log.WithFields("entry", f.NameInArchive, "mode", mode).Debug("skipping non-regular archive entry")
		return nil, false
	}

	hdr, err := tar.FileInfoHeader(f.FileInfo, f.LinkTarget)
	if err != nil {
		log.WithFields("entry", f.NameInArchive, "error", err).Debug("skipping archive entry with an unusable header")
		return nil, false
	}

	// carried through as-is: nothing is written through this name, and the filetree sanitizes it
	hdr.Name = f.NameInArchive
	if f.IsDir() && !strings.HasSuffix(hdr.Name, "/") {
		hdr.Name += "/"
	}
	hdr.Linkname = f.LinkTarget

	// dropped: no cataloger reads them, and the header is charged against the memory budget
	hdr.PAXRecords = nil
	hdr.Uname, hdr.Gname = "", ""
	hdr.AccessTime, hdr.ChangeTime = time.Time{}, time.Time{}
	hdr.ModTime = hdr.ModTime.Truncate(time.Second)

	return hdr, true
}
