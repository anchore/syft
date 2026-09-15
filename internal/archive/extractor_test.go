package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
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

// fileContent opens an archive already on disk as Content, which is what the extractors take now
// that an archive's bytes may be held in memory instead. Registered for close so a test that opens
// several does not leak handles.
func fileContent(t *testing.T, path string) Content {
	t.Helper()
	c, err := OpenFileContent(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	return c
}

// diskCharge returns a charge against a disk limit of the given size, for a test that wants the byte
// bound to bite without standing up a whole scan.
func diskCharge(max int64) *Charge {
	return NewLimiter(Limits{MaxDiskBytes: max}).Charge()
}

// sortedNames fixes the entry order of a test archive. Limits are enforced as the walk proceeds, so
// which entries land before a truncation is a function of entry order and a map's order is random.
func sortedNames(files map[string]string) []string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// overflowEntry is one entry read back out of an overflow tar. Assertions are made against these rather
// than against files in a directory, because an archive's entries are now headers in one file.
type overflowEntry struct {
	name       string
	body       string
	linkTarget string
	mode       fs.FileMode
	typeflag   byte
}

// overflowFor makes the one tar an archive's entries are written into, in the test's own temp space.
func overflowFor(t *testing.T) *OverflowTar {
	t.Helper()
	s, err := newOverflowTar(filepath.Join(t.TempDir(), overflowTarName))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// readOverflow reads an overflow tar back, keyed by entry name. It closes the tar first: the writer holds
// it open for the header rewrites that give each entry the size that actually arrived.
func readOverflow(t *testing.T, s *OverflowTar) map[string]overflowEntry {
	t.Helper()
	require.NoError(t, s.Close())

	f, err := os.Open(s.Path())
	require.NoError(t, err)
	defer f.Close()

	out := map[string]overflowEntry{}
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		body, err := io.ReadAll(tr)
		require.NoError(t, err)
		out[hdr.Name] = overflowEntry{
			name:       hdr.Name,
			body:       string(body),
			linkTarget: hdr.Linkname,
			mode:       hdr.FileInfo().Mode(),
			typeflag:   hdr.Typeflag,
		}
	}
	return out
}

// overflowNames is the entry names an overflow tar holds, sorted.
func overflowNames(t *testing.T, s *OverflowTar) []string {
	t.Helper()
	entries := readOverflow(t, s)
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

func TestZipExtractor_CanExtract(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	zipPath := createTestZip(t, dir, map[string]string{"hello.txt": "world"})

	ext := &ZipExtractor{}

	assert.True(t, ext.CanExtract(ctx, fileContent(t, zipPath)))

	// non-zip file
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
	overflow := overflowFor(t)

	result, err := ext.Extract(ctx, fileContent(t, zipPath), overflow, ExtractionLimits{})
	require.NoError(t, err)
	assert.Equal(t, 2, result.FilesExtracted)

	// both entries are in the one tar, under their own names and with their own content
	entries := readOverflow(t, overflow)
	assert.Equal(t, "content1", entries["file1.txt"].body)
	assert.Equal(t, "content2", entries["dir/file2.txt"].body)

	// and the archive occupies exactly one filesystem entry, which is the whole point
	info, err := os.Stat(overflow.Path())
	require.NoError(t, err)
	assert.True(t, info.Mode().IsRegular())
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
	overflow := overflowFor(t)

	// reaching a limit is a truncation, not a failure: what was written before the limit stays in the
	// tar so the caller can still catalog it. Two entries of one byte each cost two header blocks and
	// two data blocks, so four blocks of room admits two entries and refuses the third.
	result, err := ext.Extract(ctx, fileContent(t, zipPath), overflow, ExtractionLimits{
		Charge: diskCharge(4 * 512),
	})
	require.NoError(t, err)
	assert.True(t, result.Truncated())
	assert.Equal(t, TruncatedByDiskLimit, result.Truncation)
	assert.Equal(t, 2, result.FilesExtracted)

	assert.Equal(t, []string{"file1.txt", "file2.txt"}, overflowNames(t, overflow),
		"the two entries written before the limit must still be readable")
}

func TestZipExtractor_Extract_SizeLimitReached(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	files := map[string]string{
		"file1.txt": strings.Repeat("x", 100),
	}
	zipPath := createTestZip(t, dir, files)

	ext := &ZipExtractor{}
	overflow := overflowFor(t)

	result, err := ext.Extract(ctx, fileContent(t, zipPath), overflow, ExtractionLimits{Charge: diskCharge(50)})
	require.NoError(t, err)
	assert.True(t, result.Truncated())
	assert.Equal(t, TruncatedByDiskLimit, result.Truncation)

	// the single entry blew the budget on its own, so it is dropped rather than left half-written:
	// a partial jar or pom that a cataloger parses anyway is worse than an absent one. The budget is
	// spent on the entry's header before any of its content, because a header is bytes on disk too.
	assert.Zero(t, result.FilesExtracted)
	assert.Zero(t, result.BytesWritten)
	assert.Empty(t, overflowNames(t, overflow), "the over-limit entry must not be left behind")
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
	overflow := overflowFor(t)

	result, err := ext.Extract(ctx, fileContent(t, tarPath), overflow, ExtractionLimits{})
	require.NoError(t, err)

	// a compressed tar is decompressed once into the overflow file and never walked, so the extractor
	// counts nothing: how many entries this archive contributes is the index's answer, reported by
	// ExtractToResolver. What the extractor promises is that the file it produced is that tar.
	assert.Zero(t, result.FilesExtracted, "a tar is copied, not walked; the index does the counting")
	assert.NotZero(t, result.BytesWritten)

	entries := readOverflow(t, overflow)
	assert.Equal(t, "content1", entries["file1.txt"].body)
	assert.Equal(t, "content2", entries["dir/file2.txt"].body)
}

func TestFindExtractor(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	extractors := DefaultExtractors()

	// zip file should match
	zipPath := createTestZip(t, dir, map[string]string{"hello.txt": "world"})
	ext := FindExtractor(ctx, extractors, fileContent(t, zipPath))
	require.NotNil(t, ext)
	assert.IsType(t, &ZipExtractor{}, ext)

	// tar.gz should match
	tarPath := createTestTarGz(t, dir, map[string]string{"hello.txt": "world"})
	ext = FindExtractor(ctx, extractors, fileContent(t, tarPath))
	require.NotNil(t, ext)
	assert.IsType(t, &TarExtractor{}, ext)

	// non-archive should return nil
	textPath := filepath.Join(dir, "plain.txt")
	require.NoError(t, os.WriteFile(textPath, []byte("just text"), 0o644))
	ext = FindExtractor(ctx, extractors, fileContent(t, textPath))
	assert.Nil(t, ext)
}

func TestFindExtractor_NoReaders(t *testing.T) {
	// content no extractor claims yields nil rather than an error, which is how a file that matched a
	// broad mime filter but is not an archive gets skipped
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

	// create a plain text file
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

	// tar extractor should NOT claim to handle zip files
	assert.False(t, ext.CanExtract(ctx, fileContent(t, zipPath)))
}

func TestDefaultExtractionLimits(t *testing.T) {
	limits := DefaultExtractionLimits(cataloging.ArchiveSearchConfig{})
	assert.Nil(t, limits.Charge, "the charge belongs to one archive, so the config cannot supply it")
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
	// An entry named "../../etc/passwd" no longer has anywhere to go: it becomes a field in a tar
	// header, and writing a header traverses no path. So the extraction succeeds and nothing is
	// created anywhere, where before the entry was refused outright and the archive failed with it.
	// Where the name still matters is the path the SBOM reports, and that is clamped when the tar is
	// indexed - see the archive resolver's own tests.
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
	overflow := overflowFor(t)

	result, err := ext.Extract(ctx, fileContent(t, zipPath), overflow, ExtractionLimits{})
	require.NoError(t, err)
	assert.Equal(t, 1, result.FilesExtracted)

	// nothing is created outside the tar, at the traversed path or anywhere else
	_, statErr := os.Stat(filepath.Join(dir, "etc", "passwd"))
	assert.True(t, os.IsNotExist(statErr))
	_, statErr = os.Stat(filepath.Join(filepath.Dir(overflow.Path()), "etc"))
	assert.True(t, os.IsNotExist(statErr))

	// the name is carried through unsanitized, because this is the archive's own record of what it
	// held; sanitizing happens once, where the logical filetree is built
	assert.Equal(t, []string{"../../etc/passwd"}, overflowNames(t, overflow))
}

func TestTarExtractor_Extract_SymlinkIsRecordedAsALink(t *testing.T) {
	// A symlink entry is recorded as a symlink header carrying its target, not as a regular file
	// containing the target as bytes and not as a link on the real filesystem. Nothing is created, so
	// there is nothing for a target to redirect; where the link points is decided inside the archive's
	// own filetree when the tar is indexed.
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
	overflow := overflowFor(t)

	_, err = ext.Extract(ctx, fileContent(t, tarPath), overflow, ExtractionLimits{})
	require.NoError(t, err)

	entries := readOverflow(t, overflow)
	link := entries["link.txt"]
	assert.Equal(t, byte(tar.TypeSymlink), link.typeflag, "link.txt must stay a link, not become a file")
	assert.Equal(t, "real.txt", link.linkTarget)
	assert.Empty(t, link.body, "a link carries a target, not content")
	assert.Equal(t, "real content", entries["real.txt"].body)

	// and no link exists on the real filesystem beside the tar
	_, statErr := os.Lstat(filepath.Join(filepath.Dir(overflow.Path()), "link.txt"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestTarExtractor_Extract_SymlinkEscapingRootCreatesNothing(t *testing.T) {
	// A link target climbing out of the archive used to be refused at extraction, because extraction
	// created a real link that a later entry could be written through. Now the entry is a header: the
	// target is recorded as the archive gave it and nothing is created, so there is no write to
	// redirect. The target is clamped to the archive's own root when the filetree is built, which is
	// what keeps it from naming the host - see the archive resolver's own tests.
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
	overflow := overflowFor(t)

	_, err = ext.Extract(ctx, fileContent(t, tarPath), overflow, ExtractionLimits{})
	require.NoError(t, err)

	// nothing on the real filesystem beside the tar
	_, statErr := os.Lstat(filepath.Join(filepath.Dir(overflow.Path()), "passwd"))
	assert.True(t, os.IsNotExist(statErr), "no link may be created for an escaping symlink")

	entries := readOverflow(t, overflow)
	assert.Equal(t, byte(tar.TypeSymlink), entries["passwd"].typeflag)
	assert.Equal(t, "../../../../etc/passwd", entries["passwd"].linkTarget)
}

func TestTarExtractor_Extract_AbsoluteSymlinkTargetCreatesNothing(t *testing.T) {
	// An absolute target had to be rejected while extraction created real links: os.Symlink writes the
	// literal string, so reading the link resolved on the host filesystem whatever was checked at
	// extraction time. A header write creates no link, so there is nothing that resolves anywhere;
	// the target is re-rooted inside the archive when the filetree is built.
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
	overflow := overflowFor(t)

	_, err = ext.Extract(ctx, fileContent(t, tarPath), overflow, ExtractionLimits{})
	require.NoError(t, err)

	_, statErr := os.Lstat(filepath.Join(filepath.Dir(overflow.Path()), "shadow"))
	assert.True(t, os.IsNotExist(statErr), "no link may be created for an absolute target")

	entries := readOverflow(t, overflow)
	assert.Equal(t, "/etc/shadow", entries["shadow"].linkTarget)
}

func TestZipExtractor_Extract_ReadOnlyDirectoryPermissions(t *testing.T) {
	// JARs may contain directory entries with read-only permissions (e.g., META-INF/ with mode 0o555).
	// The extractor must still be able to write files into those directories.
	dir := t.TempDir()
	ctx := context.Background()

	zipPath := filepath.Join(dir, "readonly-dirs.zip")
	f, err := os.Create(zipPath)
	require.NoError(t, err)

	w := zip.NewWriter(f)

	// create a directory entry with read-only permissions (0o555)
	dirHeader := &zip.FileHeader{
		Name: "META-INF/",
	}
	dirHeader.SetMode(0o555)
	_, err = w.CreateHeader(dirHeader)
	require.NoError(t, err)

	// create a file inside that directory
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
	overflow := overflowFor(t)

	result, err := ext.Extract(ctx, fileContent(t, zipPath), overflow, ExtractionLimits{})
	require.NoError(t, err)
	// two entries: the directory and the file. A directory carries no bytes of its own, but its header
	// and padding are charged to the disk limit, which is what bounds an archive of nothing but
	// directories.
	assert.Equal(t, 2, result.FilesExtracted)

	// the directory's mode no longer decides whether the file beside it can be written - nothing is
	// written into a directory - but both entries must be recorded, modes and all
	entries := readOverflow(t, overflow)
	assert.Equal(t, "Manifest-Version: 1.0", entries["META-INF/MANIFEST.MF"].body)
	assert.Equal(t, fs.FileMode(0o555), entries["META-INF/"].mode.Perm())
	assert.Equal(t, byte(tar.TypeDir), entries["META-INF/"].typeflag)
}

func TestTarExtractor_Extract_ReadOnlyDirectoryPermissions(t *testing.T) {
	// Tar archives may contain directory entries with read-only permissions.
	// The extractor must still be able to write files into those directories.
	dir := t.TempDir()
	ctx := context.Background()

	tarPath := filepath.Join(dir, "readonly-dirs.tar.gz")
	f, err := os.Create(tarPath)
	require.NoError(t, err)

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	// write a directory entry with read-only permissions
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name:     "META-INF/",
		Typeflag: tar.TypeDir,
		Mode:     0o555,
	}))

	// write a file inside that directory
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
	overflow := overflowFor(t)

	_, err = ext.Extract(ctx, fileContent(t, tarPath), overflow, ExtractionLimits{})
	require.NoError(t, err)

	entries := readOverflow(t, overflow)
	assert.Equal(t, "Manifest-Version: 1.0", entries["META-INF/MANIFEST.MF"].body)
	assert.Equal(t, fs.FileMode(0o555), entries["META-INF/"].mode.Perm())
}

func TestZipExtractor_Extract_nonPositiveLimitDisablesOnlyThatLimit(t *testing.T) {
	// <= 0 means "no limit" per limit, so a caller can opt out of one without opting out of all of
	// them. Substituting a default here would silently re-impose a limit the user turned off.
	dir := t.TempDir()
	ctx := context.Background()

	files := map[string]string{}
	for i := range 20 {
		files[fmt.Sprintf("file%02d.txt", i)] = "x"
	}
	files["big.txt"] = strings.Repeat("y", 500)
	zipPath := createTestZip(t, dir, files)

	t.Run("the disk limit bites", func(t *testing.T) {
		result, err := (&ZipExtractor{}).Extract(ctx, fileContent(t, zipPath), overflowFor(t), ExtractionLimits{
			Charge: diskCharge(100),
		})
		require.NoError(t, err)
		assert.Equal(t, TruncatedByDiskLimit, result.Truncation, "the disk limit must still bite")
	})

	t.Run("unbounded extracts everything", func(t *testing.T) {
		result, err := (&ZipExtractor{}).Extract(ctx, fileContent(t, zipPath), overflowFor(t), ExtractionLimits{})
		require.NoError(t, err)
		assert.False(t, result.Truncated())
		assert.Equal(t, len(files), result.FilesExtracted)
	})
}

func TestZipExtractor_Extract_dataEdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("empty archive is a non-event", func(t *testing.T) {
		dir := t.TempDir()
		zipPath := createTestZip(t, dir, map[string]string{})

		result, err := (&ZipExtractor{}).Extract(ctx, fileContent(t, zipPath), overflowFor(t), ExtractionLimits{})
		require.NoError(t, err, "a valid archive containing nothing is not a failure")
		assert.Zero(t, result.FilesExtracted)
		assert.False(t, result.Truncated())
	})

	t.Run("zero-byte entry is recorded", func(t *testing.T) {
		dir := t.TempDir()
		zipPath := createTestZip(t, dir, map[string]string{"empty.txt": ""})
		overflow := overflowFor(t)

		result, err := (&ZipExtractor{}).Extract(ctx, fileContent(t, zipPath), overflow, ExtractionLimits{})
		require.NoError(t, err)
		assert.Equal(t, 1, result.FilesExtracted)

		// its header and the end-of-archive marker are bytes on disk even though the entry carries
		// none, which is exactly why the disk limit counts what is written rather than entry sizes
		assert.Equal(t, int64(3*tarBlockSize), result.BytesWritten)

		entries := readOverflow(t, overflow)
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

		overflow := overflowFor(t)

		_, err = (&ZipExtractor{}).Extract(ctx, fileContent(t, zipPath), overflow, ExtractionLimits{})
		require.NoError(t, err)

		// it is one entry in the tar and nothing at the host path; the leading slash is dropped when
		// the filetree is built, so it reads as a path inside this archive
		assert.Equal(t, "pwned", readOverflow(t, overflow)["/etc/hosts"].body)
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
		overflow := overflowFor(t)

		result, err := (&ZipExtractor{}).Extract(ctx, fileContent(t, zipPath), overflow, ExtractionLimits{})
		require.NoError(t, err)
		assert.Equal(t, len(names), result.FilesExtracted)

		entries := readOverflow(t, overflow)
		for name, want := range names {
			require.Contains(t, entries, name, "entry %q must be recorded under its own name", name)
			assert.Equal(t, want, entries[name].body)
		}
	})
}

func TestExtract_diskLimitTruncatesOneArchive(t *testing.T) {
	// the disk limit is enforced as the entries land, not between archives: a bound checked only
	// between archives lets one archive overshoot by everything it writes.
	//
	// The budget is expressed in tar blocks because that is now what an entry costs: a 512-byte header
	// plus its content padded up to the next block. Two entries here cost one block of header and one
	// of data each, so a budget of two and a half entries' worth admits the first whole and refuses
	// the second at its header.
	ctx := context.Background()
	files := map[string]string{
		"a/small.txt": strings.Repeat("s", 50),
		"b/big.txt":   strings.Repeat("b", 500),
	}

	dir := t.TempDir()
	archivePath := createTestZip(t, dir, files)
	overflow := overflowFor(t)

	charge := diskCharge(3 * tarBlockSize)
	result, err := (&ZipExtractor{}).Extract(ctx, fileContent(t, archivePath), overflow, ExtractionLimits{Charge: charge})
	require.NoError(t, err, "reaching a limit is a truncation, not a failure")

	assert.Equal(t, TruncatedByDiskLimit, result.Truncation,
		"a limit breach reports its own reason, so the log can name which bound was reached")
	assert.Equal(t, 1, result.FilesExtracted)
	assert.Equal(t, int64(2*tarBlockSize), result.BytesWritten, "one header and one padded data block")

	_, disk := charge.Held()
	assert.Equal(t, int64(2*tarBlockSize), disk,
		"the limiter holds exactly what landed: the dropped entry's header is refunded")

	// the partial tar is still a readable tar: what was written before the limit filled stays, and the
	// entry that did not fit is absent rather than short
	entries := readOverflow(t, overflow)
	assert.Len(t, entries["a/small.txt"].body, 50)
	assert.NotContains(t, entries, "b/big.txt")
}

func TestTarExtractor_Extract_diskLimitTruncatesTheCopy(t *testing.T) {
	// a tar-family archive is copied rather than walked, so the disk limit stops it at a copy chunk
	// rather than on an entry boundary. What is left is a tar that ends part way through an entry, and
	// keeping the entries that precede that point is the indexer's job - see the archive resolver's
	// tests. Here the assertion is that the copy stops, says why, and holds only what it wrote.
	ctx := context.Background()
	dir := t.TempDir()

	// two entries either side of a copy chunk, so the limit can bite in the middle of the stream
	// rather than refusing the first chunk and writing nothing at all
	files := map[string]string{
		"a/first.txt":  strings.Repeat("a", 40*1024),
		"b/second.txt": strings.Repeat("b", 40*1024),
	}
	archivePath := createTestTarGz(t, dir, files)
	overflow := overflowFor(t)

	charge := diskCharge(64 * 1024)
	result, err := (&TarExtractor{}).Extract(ctx, fileContent(t, archivePath), overflow, ExtractionLimits{Charge: charge})
	require.NoError(t, err)

	assert.Equal(t, TruncatedByDiskLimit, result.Truncation)
	assert.Equal(t, int64(64*1024), result.BytesWritten, "every byte written was charged, and no more")

	_, disk := charge.Held()
	assert.Equal(t, result.BytesWritten, disk)

	info, err := os.Stat(overflow.Path())
	require.NoError(t, err)
	assert.Equal(t, result.BytesWritten, info.Size(), "the tar holds exactly what was charged for")
}

func TestExtract_diskLimitFallsWhenAnArchiveIsReleased(t *testing.T) {
	// the whole point of a limiter over a counter: two archives of the same size both extract in full
	// when the first is released between them, and the second is bounded when it is not
	ctx := context.Background()
	dir := t.TempDir()
	zipPath := createTestZip(t, dir, map[string]string{"a.txt": strings.Repeat("a", 200)})

	// one entry of 200 bytes costs a header block, a padded data block and the end-of-archive marker:
	// four blocks. A limit of five leaves no room for a second archive while the first is held.
	const oneArchive = 4 * tarBlockSize
	limiter := NewLimiter(Limits{MaxDiskBytes: 5 * tarBlockSize})

	first := limiter.Charge()
	result, err := (&ZipExtractor{}).Extract(ctx, fileContent(t, zipPath), overflowFor(t), ExtractionLimits{Charge: first})
	require.NoError(t, err)
	require.False(t, result.Truncated())
	require.Equal(t, int64(oneArchive), result.BytesWritten)

	t.Run("a second archive is bounded while the first is still held", func(t *testing.T) {
		second := limiter.Charge()
		result, err := (&ZipExtractor{}).Extract(ctx, fileContent(t, zipPath), overflowFor(t), ExtractionLimits{Charge: second})
		require.NoError(t, err)
		assert.Equal(t, TruncatedByDiskLimit, result.Truncation)
		second.Release()
	})

	t.Run("and extracts in full once the first is released", func(t *testing.T) {
		first.Release()
		_, disk := limiter.InUse()
		require.Zero(t, disk, "releasing every charge must take the limiter back to nothing")

		third := limiter.Charge()
		result, err := (&ZipExtractor{}).Extract(ctx, fileContent(t, zipPath), overflowFor(t), ExtractionLimits{Charge: third})
		require.NoError(t, err)
		assert.False(t, result.Truncated(), "a counter would have refused this; a limiter does not")
		assert.Equal(t, int64(oneArchive), result.BytesWritten)
	})
}

// createDirOnlyZip writes a zip of nothing but directory entries.
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

// createDirOnlyTarGz writes a gzipped tar of nothing but directory entries.
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

func TestExtract_directoryEntriesAreBoundedByDisk(t *testing.T) {
	// an archive of directory entries alone carries no content, so what bounds it is the disk limit
	// charging each entry's header and the tar's padding. That is the resource such an archive
	// actually consumes, and it is the only bound left now that the entry count is gone.
	ctx := context.Background()

	t.Run("zip", func(t *testing.T) {
		dir := t.TempDir()
		zipPath := createDirOnlyZip(t, dir, 50)
		overflow := overflowFor(t)

		// each directory entry is one header block; room for twelve blocks admits ten entries plus the
		// two end-of-archive blocks
		result, err := (&ZipExtractor{}).Extract(ctx, fileContent(t, zipPath), overflow, ExtractionLimits{
			Charge: diskCharge(12 * tarBlockSize),
		})
		require.NoError(t, err, "a bound is a truncation, not a failure")
		assert.Equal(t, TruncatedByDiskLimit, result.Truncation)
		assert.Less(t, result.FilesExtracted, 50, "the bound must stop the archive short")
		assert.NotEmpty(t, overflowNames(t, overflow), "what was written before the bound stays readable")
	})

	t.Run("tar.gz is copied whole, so the disk limit is what stops it", func(t *testing.T) {
		// a tar is not walked entry by entry: the copy takes the whole archive, and the disk limit is
		// charged as those bytes land
		dir := t.TempDir()
		tarPath := createDirOnlyTarGz(t, dir, 50)
		overflow := overflowFor(t)

		result, err := (&TarExtractor{}).Extract(ctx, fileContent(t, tarPath), overflow, ExtractionLimits{
			Charge: diskCharge(-1),
		})
		require.NoError(t, err)
		assert.False(t, result.Truncated())
		assert.Len(t, overflowNames(t, overflow), 50)
	})
}

// symlinkEntry describes one archive entry for the escape tests: a symlink when linkTarget is set,
// a regular file otherwise.
type symlinkEntry struct {
	name       string
	linkTarget string
	body       string
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
			// a zip stores a symlink as an entry whose mode carries the symlink bit and whose
			// content is the link target
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

// findEscapedFiles returns every path under base, outside destDir, whose basename is name.
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

func TestExtract_symlinkChainEscapeWritesNothing(t *testing.T) {
	// two cooperating link entries used to each pass a lexical check and together resolve outside the
	// extraction directory: "d" -> "." landed on the root, so "d/up" -> ".." was created AS
	// "<root>/up" -> ".." and pointed above it, and a third entry was written through it.
	//
	// The chain needed real links on a real filesystem to work. Entries are headers now, so the whole
	// class is gone rather than closed: no link is created, so there is nothing for a later entry to
	// be written through, and no entry is written anywhere in the first place. The archive is kept in
	// the suite because "nothing outside the tar is created" is the property to keep asserting, and
	// this is the input that would have violated it.
	chain := []symlinkEntry{
		{name: "d", linkTarget: "."},
		{name: "d/up", linkTarget: ".."},
		{name: "up/PWNED", body: "arbitrary write"},
	}

	// three link pairs, each climbing one more level. A fix that only walked one level would pass a
	// one-level test and still let this through.
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

func assertNoEscape(t *testing.T, build func(*testing.T, string, string, []symlinkEntry) string, newExtractor func() Extractor, archiveName string, entries []symlinkEntry) {
	t.Helper()

	// several levels of headroom above the extraction directory, all inside the test's own temp
	// tree, so an escape has somewhere to land and is still cleaned up
	base := t.TempDir()
	destDir := filepath.Join(base, "one", "two", "three", "contents")
	require.NoError(t, os.MkdirAll(destDir, 0o755))

	archivePath := build(t, base, archiveName, entries)

	overflow, err := newOverflowTar(filepath.Join(destDir, overflowTarName))
	require.NoError(t, err)
	t.Cleanup(func() { _ = overflow.Close() })

	_, err = newExtractor().Extract(context.Background(), fileContent(t, archivePath), overflow, ExtractionLimits{})
	require.NoError(t, err, "an unsafe entry is skipped, not a failure of the whole archive")

	assert.Empty(t, findEscapedFiles(t, base, destDir, "PWNED"),
		"nothing may be written outside the extraction directory")

	// and nothing was created inside it either, other than the one tar
	created, err := os.ReadDir(destDir)
	require.NoError(t, err)
	require.Len(t, created, 1)
	assert.Equal(t, overflowTarName, created[0].Name())
}

func TestTarExtractor_Extract_legitimateRelativeSymlinkIsCarriedThrough(t *testing.T) {
	// containing an escape must not cost what real archives contain: a relative link into a sibling
	// directory of the archive's own tree keeps its target verbatim, so the filetree can resolve it.
	// That it then resolves is asserted where resolution happens, in the archive resolver's tests.
	dir := t.TempDir()

	archivePath := createSymlinkChainTarGz(t, dir, "legit.tar.gz", []symlinkEntry{
		{name: "lib/real.txt", body: "real content"},
		{name: "bin/link.txt", linkTarget: "../lib/real.txt"},
		{name: "lib/sub/deep.txt", body: "deep"},
		{name: "bin/deep.txt", linkTarget: "../lib/sub/deep.txt"},
	})
	overflow := overflowFor(t)

	_, err := (&TarExtractor{}).Extract(context.Background(), fileContent(t, archivePath), overflow, ExtractionLimits{})
	require.NoError(t, err)

	entries := readOverflow(t, overflow)
	assert.Equal(t, "../lib/real.txt", entries["bin/link.txt"].linkTarget)
	assert.Equal(t, "../lib/sub/deep.txt", entries["bin/deep.txt"].linkTarget)
	assert.Equal(t, "real content", entries["lib/real.txt"].body)
	assert.Equal(t, "deep", entries["lib/sub/deep.txt"].body)
}

func TestExtract_siblingOfExtractionDirectoryWritesNothing(t *testing.T) {
	// the realistic form of the string-prefix hole SafeJoin was fixed for: an entry naming
	// "../contents-evil/..." shares the extraction directory's prefix and is outside it.
	//
	// Both extractors used to fail the archive here, because SafeJoin refused the entry. Nothing joins
	// an entry name to a path any more, so the entry is recorded as the name it claims and no
	// filesystem path is derived from it at all. The assertion that matters is unchanged: nothing is
	// written beside the extraction directory.
	ctx := context.Background()

	for _, tc := range []struct {
		name    string
		build   func(t *testing.T, dir string, files map[string]string) string
		extract func(path string, overflow *OverflowTar) (ExtractionResult, error)
	}{
		{
			name:  "zip",
			build: createTestZip,
			extract: func(path string, overflow *OverflowTar) (ExtractionResult, error) {
				return (&ZipExtractor{}).Extract(ctx, fileContent(t, path), overflow, ExtractionLimits{})
			},
		},
		{
			name:  "tar.gz",
			build: createTestTarGz,
			extract: func(path string, overflow *OverflowTar) (ExtractionResult, error) {
				return (&TarExtractor{}).Extract(ctx, fileContent(t, path), overflow, ExtractionLimits{})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			destDir := filepath.Join(base, "contents")
			require.NoError(t, os.MkdirAll(destDir, 0o755))

			archivePath := tc.build(t, base, map[string]string{"../contents-evil/x.txt": "escaped"})

			overflow, err := newOverflowTar(filepath.Join(base, overflowTarName))
			require.NoError(t, err)
			t.Cleanup(func() { _ = overflow.Close() })

			_, err = tc.extract(archivePath, overflow)
			require.NoError(t, err, "a hostile name is a header field, not a failure")

			_, statErr := os.Stat(filepath.Join(base, "contents-evil", "x.txt"))
			assert.True(t, os.IsNotExist(statErr),
				"nothing may be written to a sibling of the extraction directory")

			entries, err := os.ReadDir(destDir)
			require.NoError(t, err)
			assert.Empty(t, entries, "the extraction directory stays empty: entries live in the tar")

			assert.Equal(t, "escaped", readOverflow(t, overflow)["../contents-evil/x.txt"].body)
		})
	}
}

// scriptPrefixedZip is a self-extracting archive in the shape Spring Boot produces: a launcher
// script with a complete zip concatenated onto it. Built rather than committed, so what makes the
// case is visible in the test.
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
	// the regression this closes: a Spring Boot executable jar sniffs as text/x-shellscript, so
	// format identification refuses it and every package inside is lost
	data := scriptPrefixedZip(t, "#!/bin/bash\necho launcher\nexit 0\n", map[string]string{
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n",
		"BOOT-INF/lib/dep.jar": "not really a jar, just bytes",
	})

	extractor := &ZipExtractor{}
	require.True(t, extractor.CanExtract(context.Background(), bytesContent("app.jar", data)),
		"a zip behind a launcher script must be recognized")

	// and it extracts, because archive/zip finds the central directory from the end
	overflow, err := newOverflowTar(filepath.Join(t.TempDir(), "app.jar.tar"))
	require.NoError(t, err)
	result, err := extractor.Extract(context.Background(), bytesContent("app.jar", data), overflow,
		ExtractionLimits{Charge: diskCharge(-1)})
	require.NoError(t, err)
	assert.Positive(t, result.BytesWritten, "the entries behind the script prefix must actually be written")
	assert.Empty(t, string(result.Truncation))
}

func Test_ZipExtractor_refusesANonArchiveThatNothingIdentifies(t *testing.T) {
	// the probe must not turn a file with no central directory into an archive. Note the name matters
	// here in a way it does not in a scan: identification matches on it, so `notes.zip` is claimed by
	// name before the probe is reached. That is why the scenario `misnamed non-archive is not
	// extracted` is asserted at the task level, where the candidate set decides - see
	// Test_archiveCataloger_aMisnamedNonArchiveIsNotAnError.
	extractor := &ZipExtractor{}
	for _, name := range []string{"app.jar", "bundle", "launcher"} {
		t.Run(name, func(t *testing.T) {
			content := bytesContent(name, []byte("plain text, no central directory anywhere in it"))
			assert.False(t, extractor.CanExtract(context.Background(), content))
		})
	}
}
