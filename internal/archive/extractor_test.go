package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cataloging"
)

// storedEntry is one entry read back out of an EntryStore. Assertions run against these rather than
// files in a directory, since an archive's entries are headers and bytes in a store.
type storedEntry struct {
	name       string
	body       string
	linkTarget string
	mode       fs.FileMode
	typeflag   byte
}

func TestZipExtractor_CanExtract(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	zipPath := createTestZip(t, dir, map[string]string{"hello.txt": "world"})

	ext := &ZipExtractor{}

	assert.True(t, ext.CanExtract(ctx, fileContent(t, zipPath)))

	nonZipPath := filepath.Join(dir, "notazip.txt")
	require.NoError(t, os.WriteFile(nonZipPath, []byte("just text"), 0o644))

	assert.False(t, ext.CanExtract(ctx, fileContent(t, nonZipPath)))
}

func TestZipExtractor_Extract(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	files := map[string]string{
		"file1.txt":     "content1",
		"dir/file2.txt": "content2",
	}
	zipPath := createTestZip(t, dir, files)

	ext := &ZipExtractor{}
	overflow := storeFor(t)

	_, err := ext.Extract(ctx, fileContent(t, zipPath), overflow, nil)
	require.NoError(t, err)
	assert.Len(t, overflow.Entries(), 2)

	// both entries are in the one store, under their own names and with their own content
	entries := readStore(t, overflow)
	assert.Equal(t, "content1", entries["file1.txt"].body)
	assert.Equal(t, "content2", entries["dir/file2.txt"].body)

	// and with no bound to push them out, nothing was written to disk at all
	assert.Zero(t, overflow.OnDisk())
	assert.NoFileExists(t, filepath.Join(storeDir(t, overflow), overflowBlobName))
}

func TestZipExtractor_Extract_FileLimitReached(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	files := map[string]string{
		"file1.txt": "a",
		"file2.txt": "b",
		"file3.txt": "c",
	}
	zipPath := createTestZip(t, dir, files)

	ext := &ZipExtractor{}
	overflow := storeFor(t)

	// reaching a limit truncates rather than fails: what was stored stays catalogable. Each entry costs
	// its index record plus its one byte of content, so two entries' worth of room refuses the third.
	record := indexRecordCost(tar.Header{Name: "file1.txt"})
	result, err := ext.Extract(ctx, fileContent(t, zipPath), overflow, diskCharge(2*(record+1)+record))
	require.NoError(t, err)
	assert.True(t, result.Truncated())
	assert.Equal(t, TruncatedByDiskLimit, result.Truncation)

	entries := readStore(t, overflow)
	assert.Equal(t, "a", entries["file1.txt"].body)
	assert.Equal(t, "b", entries["file2.txt"].body,
		"the two entries stored before the limit must still be readable")
	assert.Empty(t, entries["file3.txt"].body, "the entry the limit refused holds no content")
}

func TestZipExtractor_Extract_SizeLimitReached(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	files := map[string]string{
		"file1.txt": strings.Repeat("x", 100),
	}
	zipPath := createTestZip(t, dir, files)

	ext := &ZipExtractor{}
	overflow := storeFor(t)

	result, err := ext.Extract(ctx, fileContent(t, zipPath), overflow, diskCharge(50))
	require.NoError(t, err)
	assert.True(t, result.Truncated())
	assert.Equal(t, TruncatedByDiskLimit, result.Truncation)

	// the single entry blew the budget on its own, so it is dropped rather than left half-written: a
	// partial jar or pom a cataloger parses anyway is worse than an absent one. The budget goes on the
	// entry's header before any content, a header being bytes on disk too.
	assert.Empty(t, overflow.Entries())
	assert.Zero(t, overflow.OnDisk())
	assert.Empty(t, storedNames(t, overflow), "the over-limit entry must not be left behind")
}

func TestTarExtractor_CanExtract(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	tarPath := createTestTarGz(t, dir, map[string]string{"hello.txt": "world"})

	ext := &TarExtractor{}
	assert.True(t, ext.CanExtract(ctx, fileContent(t, tarPath)))
}

func TestTarExtractor_Extract(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	files := map[string]string{
		"file1.txt":     "content1",
		"dir/file2.txt": "content2",
	}
	tarPath := createTestTarGz(t, dir, files)

	ext := &TarExtractor{}
	overflow := storeFor(t)

	_, err := ext.Extract(ctx, fileContent(t, tarPath), overflow, nil)
	require.NoError(t, err)

	// a tar-family archive is walked entry by entry like any other, and with no bound pushing them out
	// its entries stay in memory
	assert.Len(t, overflow.Entries(), 2)
	assert.Zero(t, overflow.OnDisk())

	entries := readStore(t, overflow)
	assert.Equal(t, "content1", entries["file1.txt"].body)
	assert.Equal(t, "content2", entries["dir/file2.txt"].body)
}

func TestFindExtractor(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	extractors := DefaultExtractors()

	zipPath := createTestZip(t, dir, map[string]string{"hello.txt": "world"})
	ext := FindExtractor(ctx, extractors, fileContent(t, zipPath))
	require.NotNil(t, ext)
	assert.IsType(t, &ZipExtractor{}, ext)

	tarPath := createTestTarGz(t, dir, map[string]string{"hello.txt": "world"})
	ext = FindExtractor(ctx, extractors, fileContent(t, tarPath))
	require.NotNil(t, ext)
	assert.IsType(t, &TarExtractor{}, ext)

	textPath := filepath.Join(dir, "plain.txt")
	require.NoError(t, os.WriteFile(textPath, []byte("just text"), 0o644))
	ext = FindExtractor(ctx, extractors, fileContent(t, textPath))
	assert.Nil(t, ext)
}

func TestFindExtractor_NoReaders(t *testing.T) {
	// content no extractor claims yields nil rather than an error, so a file matching a broad mime
	// filter but not an archive is skipped
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "plain.txt")
	require.NoError(t, os.WriteFile(path, []byte("just text"), 0o644))

	ext := FindExtractor(ctx, DefaultExtractors(), fileContent(t, path))
	assert.Nil(t, ext)
}

func TestTarExtractor_CanExtract_NonTarFile(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	path := filepath.Join(dir, "plain.txt")
	require.NoError(t, os.WriteFile(path, []byte("not a tar"), 0o644))

	ext := &TarExtractor{}
	assert.False(t, ext.CanExtract(ctx, fileContent(t, path)))
}

func TestTarExtractor_CanExtract_ZipFileReturnsFalse(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	zipPath := createTestZip(t, dir, map[string]string{"hello.txt": "world"})

	ext := &TarExtractor{}

	assert.False(t, ext.CanExtract(ctx, fileContent(t, zipPath)))
}

func TestDefaultLimits(t *testing.T) {
	cfg := cataloging.ArchiveSearchConfig{
		MaxMemoryBytes: 111,
		MaxDiskBytes:   222,
	}
	limits := DefaultLimits(cfg)
	assert.Equal(t, int64(111), limits.MaxMemoryBytes)
	assert.Equal(t, int64(222), limits.MaxDiskBytes)
}

func TestZipExtractor_Extract_ZipSlipPrevented(t *testing.T) {
	// an entry named "../../etc/passwd" becomes a field in a tar header, and writing a header traverses
	// no path, so extraction succeeds and nothing is created anywhere. The name still matters to the
	// path the SBOM reports, which is clamped at index time - see the archive resolver's own tests.
	dir := t.TempDir()
	ctx := context.Background()

	zipPath := filepath.Join(dir, "evil.zip")
	f, err := os.Create(zipPath)
	require.NoError(t, err)

	w := zip.NewWriter(f)
	fw, err := w.Create("../../etc/passwd")
	require.NoError(t, err)
	_, err = fw.Write([]byte("evil"))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.NoError(t, f.Close())

	ext := &ZipExtractor{}
	overflow := storeFor(t)

	_, err = ext.Extract(ctx, fileContent(t, zipPath), overflow, nil)
	require.NoError(t, err)
	assert.Len(t, overflow.Entries(), 1)

	// nothing is created outside the tar, at the traversed path or anywhere else
	_, statErr := os.Stat(filepath.Join(dir, "etc", "passwd"))
	assert.True(t, os.IsNotExist(statErr))
	_, statErr = os.Stat(filepath.Join(storeDir(t, overflow), "etc"))
	assert.True(t, os.IsNotExist(statErr))

	// the name is carried through unsanitized, this being the archive's own record of what it held;
	// sanitizing happens where the logical filetree is built
	assert.Equal(t, []string{"../../etc/passwd"}, storedNames(t, overflow))
}

func TestTarExtractor_Extract_SymlinkIsRecordedAsALink(t *testing.T) {
	// a symlink entry is recorded as a symlink header carrying its target - not a regular file holding
	// the target as bytes, and not a link on the real filesystem. Nothing is created, so nothing can be
	// redirected; where the link points is decided in the archive's own filetree.
	dir := t.TempDir()
	ctx := context.Background()

	tarPath := filepath.Join(dir, "with-link.tar.gz")
	f, err := os.Create(tarPath)
	require.NoError(t, err)

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	target := []byte("real content")
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "real.txt",
		Mode: 0o644,
		Size: int64(len(target)),
	}))
	_, err = tw.Write(target)
	require.NoError(t, err)

	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name:     "link.txt",
		Linkname: "real.txt",
		Typeflag: tar.TypeSymlink,
		Mode:     0o777,
	}))

	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	require.NoError(t, f.Close())

	ext := &TarExtractor{}
	overflow := storeFor(t)

	_, err = ext.Extract(ctx, fileContent(t, tarPath), overflow, nil)
	require.NoError(t, err)

	entries := readStore(t, overflow)
	link := entries["link.txt"]
	assert.Equal(t, byte(tar.TypeSymlink), link.typeflag, "link.txt must stay a link, not become a file")
	assert.Equal(t, "real.txt", link.linkTarget)
	assert.Empty(t, link.body, "a link carries a target, not content")
	assert.Equal(t, "real content", entries["real.txt"].body)

	// and no link exists on the real filesystem beside the tar
	_, statErr := os.Lstat(filepath.Join(storeDir(t, overflow), "link.txt"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestTarExtractor_Extract_SymlinkEscapingRootCreatesNothing(t *testing.T) {
	// a link target climbing out of the archive is recorded as the archive gave it, the entry being a
	// header with nothing created for a write to be redirected through. The target is clamped to the
	// archive's own root when the filetree is built - see the archive resolver's own tests.
	dir := t.TempDir()
	ctx := context.Background()

	tarPath := filepath.Join(dir, "evil-link.tar.gz")
	f, err := os.Create(tarPath)
	require.NoError(t, err)

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name:     "passwd",
		Linkname: "../../../../etc/passwd",
		Typeflag: tar.TypeSymlink,
		Mode:     0o777,
	}))

	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	require.NoError(t, f.Close())

	ext := &TarExtractor{}
	overflow := storeFor(t)

	_, err = ext.Extract(ctx, fileContent(t, tarPath), overflow, nil)
	require.NoError(t, err)

	// nothing on the real filesystem beside the tar
	_, statErr := os.Lstat(filepath.Join(storeDir(t, overflow), "passwd"))
	assert.True(t, os.IsNotExist(statErr), "no link may be created for an escaping symlink")

	entries := readStore(t, overflow)
	assert.Equal(t, byte(tar.TypeSymlink), entries["passwd"].typeflag)
	assert.Equal(t, "../../../../etc/passwd", entries["passwd"].linkTarget)
}

func TestTarExtractor_Extract_AbsoluteSymlinkTargetCreatesNothing(t *testing.T) {
	// an absolute target creates no link either: a header write resolves nowhere, and the target is
	// re-rooted inside the archive when the filetree is built
	dir := t.TempDir()
	ctx := context.Background()

	tarPath := filepath.Join(dir, "absolute-link.tar.gz")
	f, err := os.Create(tarPath)
	require.NoError(t, err)

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name:     "shadow",
		Linkname: "/etc/shadow",
		Typeflag: tar.TypeSymlink,
		Mode:     0o777,
	}))

	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	require.NoError(t, f.Close())

	ext := &TarExtractor{}
	overflow := storeFor(t)

	_, err = ext.Extract(ctx, fileContent(t, tarPath), overflow, nil)
	require.NoError(t, err)

	_, statErr := os.Lstat(filepath.Join(storeDir(t, overflow), "shadow"))
	assert.True(t, os.IsNotExist(statErr), "no link may be created for an absolute target")

	entries := readStore(t, overflow)
	assert.Equal(t, "/etc/shadow", entries["shadow"].linkTarget)
}

func TestZipExtractor_Extract_ReadOnlyDirectoryPermissions(t *testing.T) {
	// jars may hold directory entries with read-only permissions (e.g. META-INF/ at mode 0o555); the
	// extractor must still write files into them
	dir := t.TempDir()
	ctx := context.Background()

	zipPath := filepath.Join(dir, "readonly-dirs.zip")
	f, err := os.Create(zipPath)
	require.NoError(t, err)

	w := zip.NewWriter(f)

	dirHeader := &zip.FileHeader{
		Name: "META-INF/",
	}
	dirHeader.SetMode(0o555)
	_, err = w.CreateHeader(dirHeader)
	require.NoError(t, err)

	fileHeader := &zip.FileHeader{
		Name: "META-INF/MANIFEST.MF",
	}
	fileHeader.SetMode(0o644)
	fw, err := w.CreateHeader(fileHeader)
	require.NoError(t, err)
	_, err = fw.Write([]byte("Manifest-Version: 1.0"))
	require.NoError(t, err)

	require.NoError(t, w.Close())
	require.NoError(t, f.Close())

	ext := &ZipExtractor{}
	overflow := storeFor(t)

	_, err = ext.Extract(ctx, fileContent(t, zipPath), overflow, nil)
	require.NoError(t, err)
	// two entries: the directory and the file. A directory carries no bytes of its own, but its index
	// record is charged, which is what bounds an archive of nothing but directories.
	assert.Len(t, overflow.Entries(), 2)

	// nothing is written into a directory, so its mode decides nothing, but both entries must be
	// recorded, modes and all
	entries := readStore(t, overflow)
	assert.Equal(t, "Manifest-Version: 1.0", entries["META-INF/MANIFEST.MF"].body)
	assert.Equal(t, fs.FileMode(0o555), entries["META-INF/"].mode.Perm())
	assert.Equal(t, byte(tar.TypeDir), entries["META-INF/"].typeflag)
}

func TestTarExtractor_Extract_ReadOnlyDirectoryPermissions(t *testing.T) {
	// tars may hold directory entries with read-only permissions; the extractor must still write files
	// into them
	dir := t.TempDir()
	ctx := context.Background()

	tarPath := filepath.Join(dir, "readonly-dirs.tar.gz")
	f, err := os.Create(tarPath)
	require.NoError(t, err)

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name:     "META-INF/",
		Typeflag: tar.TypeDir,
		Mode:     0o555,
	}))

	content := []byte("Manifest-Version: 1.0")
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "META-INF/MANIFEST.MF",
		Mode: 0o644,
		Size: int64(len(content)),
	}))
	_, err = tw.Write(content)
	require.NoError(t, err)

	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	require.NoError(t, f.Close())

	ext := &TarExtractor{}
	overflow := storeFor(t)

	_, err = ext.Extract(ctx, fileContent(t, tarPath), overflow, nil)
	require.NoError(t, err)

	entries := readStore(t, overflow)
	assert.Equal(t, "Manifest-Version: 1.0", entries["META-INF/MANIFEST.MF"].body)
	assert.Equal(t, fs.FileMode(0o555), entries["META-INF/"].mode.Perm())
}

func TestZipExtractor_Extract_nonPositiveLimitDisablesOnlyThatLimit(t *testing.T) {
	// <= 0 means "no limit", per limit, so a caller can opt out of one without the rest; substituting a
	// default would re-impose a limit the caller turned off
	dir := t.TempDir()
	ctx := context.Background()

	files := map[string]string{}
	for i := range 20 {
		files[fmt.Sprintf("file%02d.txt", i)] = "x"
	}
	files["big.txt"] = strings.Repeat("y", 500)
	zipPath := createTestZip(t, dir, files)

	t.Run("the disk limit bites", func(t *testing.T) {
		result, err := (&ZipExtractor{}).Extract(ctx, fileContent(t, zipPath), storeFor(t), diskCharge(100))
		require.NoError(t, err)
		assert.Equal(t, TruncatedByDiskLimit, result.Truncation, "the disk limit must still bite")
	})

	t.Run("unbounded extracts everything", func(t *testing.T) {
		overflow := storeFor(t)

		result, err := (&ZipExtractor{}).Extract(ctx, fileContent(t, zipPath), overflow, nil)
		require.NoError(t, err)
		assert.False(t, result.Truncated())
		assert.Len(t, overflow.Entries(), len(files))
	})
}

func TestZipExtractor_Extract_dataEdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("empty archive is a non-event", func(t *testing.T) {
		dir := t.TempDir()
		zipPath := createTestZip(t, dir, map[string]string{})

		overflow := storeFor(t)

		result, err := (&ZipExtractor{}).Extract(ctx, fileContent(t, zipPath), overflow, nil)
		require.NoError(t, err, "a valid archive containing nothing is not a failure")
		assert.Empty(t, overflow.Entries())
		assert.False(t, result.Truncated())
	})

	t.Run("zero-byte entry is recorded", func(t *testing.T) {
		dir := t.TempDir()
		zipPath := createTestZip(t, dir, map[string]string{"empty.txt": ""})
		overflow := storeFor(t)

		_, err := (&ZipExtractor{}).Extract(ctx, fileContent(t, zipPath), overflow, nil)
		require.NoError(t, err)
		assert.Len(t, overflow.Entries(), 1)

		// a store has no framing to write, so an entry carrying no content costs no disk at all
		assert.Zero(t, overflow.OnDisk())

		entries := readStore(t, overflow)
		require.Contains(t, entries, "empty.txt")
		assert.Empty(t, entries["empty.txt"].body)
	})

	t.Run("absolute entry path is contained", func(t *testing.T) {
		// distinct from ../ traversal: an entry literally named /etc/hosts must land inside the
		// extraction dir, never at the host path
		dir := t.TempDir()
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		w, err := zw.Create("/etc/hosts")
		require.NoError(t, err)
		_, err = w.Write([]byte("pwned"))
		require.NoError(t, err)
		require.NoError(t, zw.Close())

		zipPath := filepath.Join(dir, "abs.zip")
		require.NoError(t, os.WriteFile(zipPath, buf.Bytes(), 0o600))

		overflow := storeFor(t)

		_, err = (&ZipExtractor{}).Extract(ctx, fileContent(t, zipPath), overflow, nil)
		require.NoError(t, err)

		// one entry in the tar and nothing at the host path; the leading slash is dropped when the
		// filetree is built, so it reads as a path inside this archive
		assert.Equal(t, "pwned", readStore(t, overflow)["/etc/hosts"].body)
		_, statErr := os.Stat(filepath.Join(dir, "etc", "hosts"))
		assert.True(t, os.IsNotExist(statErr))
	})

	t.Run("unicode and non-ascii entry names survive", func(t *testing.T) {
		dir := t.TempDir()
		names := map[string]string{
			"café/naïve.txt": "accents",
			"日本語/ファイル.txt":   "japanese",
			"emoji-🎉.txt":    "emoji",
		}
		zipPath := createTestZip(t, dir, names)
		overflow := storeFor(t)

		_, err := (&ZipExtractor{}).Extract(ctx, fileContent(t, zipPath), overflow, nil)
		require.NoError(t, err)
		assert.Len(t, overflow.Entries(), len(names))

		entries := readStore(t, overflow)
		for name, want := range names {
			require.Contains(t, entries, name, "entry %q must be recorded under its own name", name)
			assert.Equal(t, want, entries[name].body)
		}
	})
}

func TestExtract_diskLimitTruncatesOneArchive(t *testing.T) {
	// the disk limit is enforced as entries land, not between archives: a bound checked only between
	// archives lets one archive overshoot by everything it writes.
	//
	// The budget is built from what a store charges, there being no framing: each entry's index record
	// plus the content bytes that reach the blob. It admits both records and the small entry whole, and
	// refuses the big one.
	ctx := context.Background()
	files := map[string]string{
		"a/small.txt": strings.Repeat("s", 50),
		"b/big.txt":   strings.Repeat("b", 500),
	}

	dir := t.TempDir()
	archivePath := createTestZip(t, dir, files)
	overflow := storeFor(t)

	records := indexRecordCost(tar.Header{Name: "a/small.txt"}) + indexRecordCost(tar.Header{Name: "b/big.txt"})
	charge := diskCharge(records + 50 + 100)
	result, err := (&ZipExtractor{}).Extract(ctx, fileContent(t, archivePath), overflow, charge)
	require.NoError(t, err, "reaching a limit is a truncation, not a failure")

	assert.Equal(t, TruncatedByDiskLimit, result.Truncation,
		"a limit breach reports its own reason, so the log can name which bound was reached")
	assert.Equal(t, int64(50), overflow.OnDisk(),
		"only the small entry was stored whole, and a store writes content and no framing")

	_, disk := charge.held()
	assert.Equal(t, records+50, disk, "the limiter holds the index records plus what content landed")

	// what was stored before the limit filled stays readable
	entries := readStore(t, overflow)
	assert.Len(t, entries["a/small.txt"].body, 50)

	// KNOWN GAP: the entry the limit refused stays in the store, its header claiming the size the
	// archive declared with none of the content behind it. A half-written pom a cataloger parses and
	// believes is worse than an absent one. Asserted as it stands, so a fix changes a test.
	require.Contains(t, entries, "b/big.txt")
	assert.Empty(t, entries["b/big.txt"].body, "none of the refused entry's content landed")
}

func TestTarExtractor_Extract_diskLimitStopsMidEntry(t *testing.T) {
	// a tar-family archive is walked entry by entry, so the disk limit can bite mid-entry rather than on
	// a boundary: the walk stops, says why, and the limiter holds no more than the bound
	ctx := context.Background()
	dir := t.TempDir()

	// two entries either side of a copy chunk, so the limit can bite mid-stream rather than refusing the
	// first chunk and writing nothing
	files := map[string]string{
		"a/first.txt":  strings.Repeat("a", 40*1024),
		"b/second.txt": strings.Repeat("b", 40*1024),
	}
	archivePath := createTestTarGz(t, dir, files)
	overflow := storeFor(t)

	const budget = 64 * 1024
	charge := diskCharge(budget)
	result, err := (&TarExtractor{}).Extract(ctx, fileContent(t, archivePath), overflow, charge)
	require.NoError(t, err)

	assert.Equal(t, TruncatedByDiskLimit, result.Truncation)
	assert.Greater(t, overflow.OnDisk(), int64(40*1024),
		"the first entry landed whole and the second got part way in")

	_, disk := charge.held()
	assert.LessOrEqual(t, disk, int64(budget), "the limiter never holds more than the bound")
	assert.Greater(t, disk, overflow.OnDisk(),
		"the charge also carries the index records, which are held in the store rather than written")

	info, err := os.Stat(filepath.Join(storeDir(t, overflow), overflowBlobName))
	require.NoError(t, err)
	assert.Equal(t, overflow.OnDisk(), info.Size(), "the blob holds exactly what the store reports")
}

func TestExtract_diskLimitFallsWhenAnArchiveIsReleased(t *testing.T) {
	// an in-use limit rather than a counter: two archives of the same size both extract in full when the
	// first is released between them, and the second is bounded when it is not
	ctx := context.Background()
	dir := t.TempDir()
	zipPath := createTestZip(t, dir, map[string]string{"a.txt": strings.Repeat("a", 200)})

	// one entry of 200 bytes costs its index record plus its content, there being no framing. A limit of
	// one and a half archives leaves no room for a second while the first is held.
	oneArchive := indexRecordCost(tar.Header{Name: "a.txt"}) + 200
	limiter := NewLimiter(Limits{MaxDiskBytes: oneArchive * 3 / 2})

	first := limiter.Charge()
	firstStore := storeFor(t)
	result, err := (&ZipExtractor{}).Extract(ctx, fileContent(t, zipPath), firstStore, first)
	require.NoError(t, err)
	require.False(t, result.Truncated())
	require.Equal(t, int64(200), firstStore.OnDisk())

	t.Run("a second archive is bounded while the first is still held", func(t *testing.T) {
		second := limiter.Charge()
		result, err := (&ZipExtractor{}).Extract(ctx, fileContent(t, zipPath), storeFor(t), second)
		require.NoError(t, err)
		assert.Equal(t, TruncatedByDiskLimit, result.Truncation)
		second.Release()
	})

	t.Run("and extracts in full once the first is released", func(t *testing.T) {
		first.Release()
		_, disk := limiter.InUse()
		require.Zero(t, disk, "releasing every charge must take the limiter back to nothing")

		third := limiter.Charge()
		thirdStore := storeFor(t)
		result, err := (&ZipExtractor{}).Extract(ctx, fileContent(t, zipPath), thirdStore, third)
		require.NoError(t, err)
		assert.False(t, result.Truncated(), "a counter would have refused this; a limiter does not")
		assert.Equal(t, int64(200), thirdStore.OnDisk())
	})
}

func TestExtract_directoryEntriesAreBoundedByDisk(t *testing.T) {
	// an archive of directory entries alone carries no content, so what bounds it is the disk limit
	// charging each entry's header and the tar's padding
	ctx := context.Background()

	t.Run("zip", func(t *testing.T) {
		dir := t.TempDir()
		zipPath := createDirOnlyZip(t, dir, 50)
		overflow := storeFor(t)

		// each directory entry is one header block; room for twelve admits ten entries plus the two
		// end-of-archive blocks
		result, err := (&ZipExtractor{}).Extract(ctx, fileContent(t, zipPath), overflow, diskCharge(12*512))
		require.NoError(t, err, "a bound is a truncation, not a failure")
		assert.Equal(t, TruncatedByDiskLimit, result.Truncation)
		assert.Less(t, len(overflow.Entries()), 50, "the bound must stop the archive short")
		assert.NotEmpty(t, storedNames(t, overflow), "what was written before the bound stays readable")
	})

	t.Run("tar.gz is copied whole, so the disk limit is what stops it", func(t *testing.T) {
		// a tar is not walked entry by entry: the copy takes the whole archive, and the disk limit is
		// charged as those bytes land
		dir := t.TempDir()
		tarPath := createDirOnlyTarGz(t, dir, 50)
		overflow := storeFor(t)

		result, err := (&TarExtractor{}).Extract(ctx, fileContent(t, tarPath), overflow, diskCharge(-1))
		require.NoError(t, err)
		assert.False(t, result.Truncated())
		assert.Len(t, storedNames(t, overflow), 50)
	})
}

// symlinkEntry describes one archive entry for the escape tests: a symlink when linkTarget is set,
// a regular file otherwise.
type symlinkEntry struct {
	name       string
	linkTarget string
	body       string
}

func TestExtract_symlinkChainEscapeWritesNothing(t *testing.T) {
	// two cooperating link entries that each pass a lexical check and together resolve outside the
	// extraction directory: "d" -> "." lands on the root, so "d/up" -> ".." is created as "<root>/up"
	// -> ".." pointing above it, and a third entry is written through it.
	//
	// The chain needs real links on a real filesystem. Entries are headers, so no link is created and
	// nothing can be written through one. Kept as the input that would violate "nothing outside the
	// store is created".
	chain := []symlinkEntry{
		{name: "d", linkTarget: "."},
		{name: "d/up", linkTarget: ".."},
		{name: "up/PWNED", body: "arbitrary write"},
	}

	// three link pairs, each climbing one more level: a check walking only one level would pass a
	// one-level test and still let this through
	escalating := []symlinkEntry{
		{name: "a", linkTarget: "."},
		{name: "a/b", linkTarget: ".."},
		{name: "b/c", linkTarget: "."},
		{name: "b/c/d", linkTarget: ".."},
		{name: "b/d/e", linkTarget: "."},
		{name: "b/d/e/f", linkTarget: ".."},
		{name: "b/d/f/PWNED", body: "arbitrary write, three levels up"},
	}

	for _, tc := range []struct {
		name    string
		entries []symlinkEntry
	}{
		{name: "one pair", entries: chain},
		{name: "three pairs escalating", entries: escalating},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("tar.gz", func(t *testing.T) {
				assertNoEscape(t, createSymlinkChainTarGz, func() Extractor { return &TarExtractor{} }, "chain.tar.gz", tc.entries)
			})
			t.Run("zip", func(t *testing.T) {
				assertNoEscape(t, createSymlinkChainZip, func() Extractor { return &ZipExtractor{} }, "chain.zip", tc.entries)
			})
		})
	}
}

func TestTarExtractor_Extract_legitimateRelativeSymlinkIsCarriedThrough(t *testing.T) {
	// containing an escape must not cost what real archives contain: a relative link into a sibling
	// directory of the archive's own tree keeps its target verbatim so the filetree can resolve it.
	// That it does resolve is asserted in the archive resolver's tests.
	dir := t.TempDir()

	archivePath := createSymlinkChainTarGz(t, dir, "legit.tar.gz", []symlinkEntry{
		{name: "lib/real.txt", body: "real content"},
		{name: "bin/link.txt", linkTarget: "../lib/real.txt"},
		{name: "lib/sub/deep.txt", body: "deep"},
		{name: "bin/deep.txt", linkTarget: "../lib/sub/deep.txt"},
	})
	overflow := storeFor(t)

	_, err := (&TarExtractor{}).Extract(context.Background(), fileContent(t, archivePath), overflow, nil)
	require.NoError(t, err)

	entries := readStore(t, overflow)
	assert.Equal(t, "../lib/real.txt", entries["bin/link.txt"].linkTarget)
	assert.Equal(t, "../lib/sub/deep.txt", entries["bin/deep.txt"].linkTarget)
	assert.Equal(t, "real content", entries["lib/real.txt"].body)
	assert.Equal(t, "deep", entries["lib/sub/deep.txt"].body)
}

func TestExtract_siblingOfExtractionDirectoryWritesNothing(t *testing.T) {
	// the realistic form of the string-prefix hole SafeJoin was fixed for: an entry naming
	// "../contents-evil/..." shares the extraction directory's prefix and is outside it.
	//
	// Nothing joins an entry name to a filesystem path, so the entry is recorded as the name it claims
	// and no path is derived from it. The assertion: nothing is written beside the extraction directory.
	ctx := context.Background()

	for _, tc := range []struct {
		name    string
		build   func(t *testing.T, dir string, files map[string]string) string
		extract func(path string, sink EntrySink) (ExtractionResult, error)
	}{
		{
			name:  "zip",
			build: createTestZip,
			extract: func(path string, sink EntrySink) (ExtractionResult, error) {
				return (&ZipExtractor{}).Extract(ctx, fileContent(t, path), sink, nil)
			},
		},
		{
			name:  "tar.gz",
			build: createTestTarGz,
			extract: func(path string, sink EntrySink) (ExtractionResult, error) {
				return (&TarExtractor{}).Extract(ctx, fileContent(t, path), sink, nil)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			destDir := filepath.Join(base, "contents")
			require.NoError(t, os.MkdirAll(destDir, 0o755))

			archivePath := tc.build(t, base, map[string]string{"../contents-evil/x.txt": "escaped"})

			store := NewEntryStore(WorkDirAt(base), "evil", nil)
			t.Cleanup(func() { _ = store.Close() })

			_, err := tc.extract(archivePath, store)
			require.NoError(t, err, "a hostile name is a header field, not a failure")

			_, statErr := os.Stat(filepath.Join(base, "contents-evil", "x.txt"))
			assert.True(t, os.IsNotExist(statErr),
				"nothing may be written to a sibling of the extraction directory")

			entries, err := os.ReadDir(destDir)
			require.NoError(t, err)
			assert.Empty(t, entries, "the extraction directory stays empty: entries live in the store")

			assert.Equal(t, "escaped", readStore(t, store)["../contents-evil/x.txt"].body)
		})
	}
}

func Test_HasZipEndOfCentralDirectory(t *testing.T) {
	var plainZip bytes.Buffer
	zw := zip.NewWriter(&plainZip)
	f, err := zw.Create("a.txt")
	require.NoError(t, err)
	_, err = f.Write([]byte("hello"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	var tarGz bytes.Buffer
	gw := gzip.NewWriter(&tarGz)
	tw := tar.NewWriter(gw)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "a.txt", Size: 5, Mode: 0o600}))
	_, err = tw.Write([]byte("hello"))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"a plain zip", plainZip.Bytes(), true},
		{
			"a zip behind a launcher script - the case content sniffing types by its head",
			scriptPrefixedZip(t, "#!/bin/bash\nexec java -jar \"$0\" \"$@\"\nexit 0\n",
				map[string]string{"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n"}),
			true,
		},
		{"prose, whatever it is named", []byte("this is not an archive, it is a sentence"), false},
		{"a tar.gz, which is an archive but not a zip", tarGz.Bytes(), false},
		{"empty", nil, false},
		{"shorter than the signature", []byte("PK"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, HasZipEndOfCentralDirectory(bytes.NewReader(tt.data)))
		})
	}
}

func Test_ZipExtractor_canExtractAZipBehindALauncherScript(t *testing.T) {
	// a Spring Boot executable jar sniffs as text/x-shellscript, which format identification refuses,
	// losing every package inside
	data := scriptPrefixedZip(t, "#!/bin/bash\necho launcher\nexit 0\n", map[string]string{
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n",
		"BOOT-INF/lib/dep.jar": "not really a jar, just bytes",
	})

	extractor := &ZipExtractor{}
	require.True(t, extractor.CanExtract(context.Background(), bytesContent("app.jar", data)),
		"a zip behind a launcher script must be recognized")

	// and it extracts, because archive/zip finds the central directory from the end
	store := storeFor(t)
	result, err := extractor.Extract(context.Background(), bytesContent("app.jar", data), store,
		diskCharge(-1))
	require.NoError(t, err)
	assert.Len(t, store.Entries(), 2, "the entries behind the script prefix must actually be stored")
	assert.Empty(t, string(result.Truncation))
	assert.Contains(t, readStore(t, store), "BOOT-INF/lib/dep.jar")
}

func Test_ZipExtractor_refusesANonArchiveThatNothingIdentifies(t *testing.T) {
	// the probe must not turn a file with no central directory into an archive. The name matters here in
	// a way it does not in a scan, since identification matches on it and `notes.zip` is claimed by name
	// before the probe is reached; the `misnamed non-archive is not extracted` scenario is therefore
	// asserted at the task level - see Test_archiveCataloger_aMisnamedNonArchiveIsNotAnError.
	extractor := &ZipExtractor{}
	for _, name := range []string{"app.jar", "bundle", "launcher"} {
		t.Run(name, func(t *testing.T) {
			content := bytesContent(name, []byte("plain text, no central directory anywhere in it"))
			assert.False(t, extractor.CanExtract(context.Background(), content))
		})
	}
}

// fileContent opens an archive already on disk as Content, which is what the extractors take.
// Registered for close so a test that opens several does not leak handles.
func fileContent(t *testing.T, path string) Content {
	t.Helper()
	c, err := openFileContent(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	return c
}

// diskCharge returns a charge against a disk limit of the given size, for a test wanting the byte
// bound to bite without standing up a whole scan.
func diskCharge(max int64) *Charge {
	return NewLimiter(Limits{MaxDiskBytes: max}).Charge()
}

// sortedNames fixes the entry order of a test archive: limits are enforced as the walk proceeds, so
// entry order decides which entries land before a truncation, and map order is random.
func sortedNames(files map[string]string) []string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// storeFor makes the sink an archive's entries are written into, in the test's own temp space.
func storeFor(t *testing.T) *EntryStore {
	t.Helper()
	s := NewEntryStore(WorkDirAt(t.TempDir()), "test-archive", nil)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// storeDir is the directory a store would spill into, for tests asserting what is and is not on disk.
func storeDir(t *testing.T, s *EntryStore) string {
	t.Helper()
	dir, err := s.workDir.Path()
	require.NoError(t, err)
	return dir
}

func readStore(t *testing.T, s *EntryStore) map[string]storedEntry {
	t.Helper()

	out := map[string]storedEntry{}
	for _, entry := range s.Entries() {
		reader, err := s.Open(entry)
		require.NoError(t, err)
		body, err := io.ReadAll(reader)
		require.NoError(t, err)
		out[entry.Header.Name] = storedEntry{
			name:       entry.Header.Name,
			body:       string(body),
			linkTarget: entry.Header.Linkname,
			mode:       entry.Header.FileInfo().Mode(),
			typeflag:   entry.Header.Typeflag,
		}
	}
	return out
}

func storedNames(t *testing.T, s *EntryStore) []string {
	t.Helper()
	entries := readStore(t, s)
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func createTestZip(t *testing.T, dir string, files map[string]string) string {
	t.Helper()
	zipPath := filepath.Join(dir, "test.zip")
	f, err := os.Create(zipPath)
	require.NoError(t, err)
	defer f.Close()

	w := zip.NewWriter(f)
	for _, name := range sortedNames(files) {
		fw, err := w.Create(name)
		require.NoError(t, err)
		_, err = fw.Write([]byte(files[name]))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return zipPath
}

func createTestTarGz(t *testing.T, dir string, files map[string]string) string {
	t.Helper()
	tarPath := filepath.Join(dir, "test.tar.gz")
	f, err := os.Create(tarPath)
	require.NoError(t, err)
	defer f.Close()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	for _, name := range sortedNames(files) {
		content := files[name]
		hdr := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		}
		require.NoError(t, tw.WriteHeader(hdr))
		_, err = tw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	return tarPath
}

func createDirOnlyZip(t *testing.T, dir string, count int) string {
	t.Helper()
	zipPath := filepath.Join(dir, "dirs.zip")
	f, err := os.Create(zipPath)
	require.NoError(t, err)
	defer f.Close()

	w := zip.NewWriter(f)
	for i := range count {
		hdr := &zip.FileHeader{Name: fmt.Sprintf("d%04d/", i)}
		hdr.SetMode(fs.ModeDir | 0o755)
		_, err := w.CreateHeader(hdr)
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return zipPath
}

func createDirOnlyTarGz(t *testing.T, dir string, count int) string {
	t.Helper()
	tarPath := filepath.Join(dir, "dirs.tar.gz")
	f, err := os.Create(tarPath)
	require.NoError(t, err)
	defer f.Close()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	for i := range count {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name:     fmt.Sprintf("d%04d/", i),
			Typeflag: tar.TypeDir,
			Mode:     0o755,
		}))
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	return tarPath
}

func createSymlinkChainTarGz(t *testing.T, dir, name string, entries []symlinkEntry) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	for _, e := range entries {
		if e.linkTarget != "" {
			require.NoError(t, tw.WriteHeader(&tar.Header{
				Name:     e.name,
				Typeflag: tar.TypeSymlink,
				Linkname: e.linkTarget,
				Mode:     0o777,
			}))
			continue
		}
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name: e.name,
			Mode: 0o644,
			Size: int64(len(e.body)),
		}))
		_, err := tw.Write([]byte(e.body))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	return path
}

func createSymlinkChainZip(t *testing.T, dir, name string, entries []symlinkEntry) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	w := zip.NewWriter(f)
	for _, e := range entries {
		hdr := &zip.FileHeader{Name: e.name}
		body := e.body
		if e.linkTarget != "" {
			// a zip stores a symlink as an entry whose mode carries the symlink bit and whose content
			// is the link target
			hdr.SetMode(fs.ModeSymlink | 0o777)
			body = e.linkTarget
		} else {
			hdr.SetMode(0o644)
		}
		fw, err := w.CreateHeader(hdr)
		require.NoError(t, err)
		_, err = fw.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return path
}

func findEscapedFiles(t *testing.T, base, destDir, name string) []string {
	t.Helper()
	var found []string
	require.NoError(t, filepath.WalkDir(base, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil // an escaping symlink can make a walk stumble; that is not the assertion
		}
		if entry.IsDir() {
			return nil
		}
		if filepath.Base(path) != name {
			return nil
		}
		if rel, relErr := filepath.Rel(destDir, path); relErr == nil && !strings.HasPrefix(rel, "..") {
			return nil
		}
		found = append(found, path)
		return nil
	}))
	return found
}

func assertNoEscape(t *testing.T, build func(*testing.T, string, string, []symlinkEntry) string, newExtractor func() Extractor, archiveName string, entries []symlinkEntry) {
	t.Helper()

	// several levels of headroom above the extraction directory, all inside the test's own temp tree, so
	// an escape has somewhere to land and is still cleaned up
	base := t.TempDir()
	destDir := filepath.Join(base, "one", "two", "three", "contents")
	require.NoError(t, os.MkdirAll(destDir, 0o755))

	archivePath := build(t, base, archiveName, entries)

	store := NewEntryStore(WorkDirAt(destDir), archiveName, nil)
	t.Cleanup(func() { _ = store.Close() })

	_, err := newExtractor().Extract(context.Background(), fileContent(t, archivePath), store, nil)
	require.NoError(t, err, "an unsafe entry is skipped, not a failure of the whole archive")

	assert.Empty(t, findEscapedFiles(t, base, destDir, "PWNED"),
		"nothing may be written outside the extraction directory")

	// and nothing was created inside it either: entries are headers and bytes in the store, and with no
	// bound pushing them out not even the overflow blob exists
	created, err := os.ReadDir(destDir)
	require.NoError(t, err)
	assert.Empty(t, created)
}

// scriptPrefixedZip is a self-extracting archive in the shape Spring Boot produces: a launcher script
// with a complete zip appended.
func scriptPrefixedZip(t *testing.T, prefix string, files map[string]string) []byte {
	t.Helper()
	var zbuf bytes.Buffer
	w := zip.NewWriter(&zbuf)
	for _, name := range sortedNames(files) {
		f, err := w.Create(name)
		require.NoError(t, err)
		_, err = f.Write([]byte(files[name]))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return append([]byte(prefix), zbuf.Bytes()...)
}

func bytesContent(name string, data []byte) Content {
	return Content{Name: name, Reader: bytes.NewReader(data)}
}
