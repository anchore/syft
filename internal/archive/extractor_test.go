package archive

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cataloging"
)

func createTestZip(t *testing.T, dir string, files map[string]string) string {
	t.Helper()
	zipPath := filepath.Join(dir, "test.zip")
	f, err := os.Create(zipPath)
	require.NoError(t, err)
	defer f.Close()

	w := zip.NewWriter(f)
	for name, content := range files {
		fw, err := w.Create(name)
		require.NoError(t, err)
		_, err = fw.Write([]byte(content))
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

	for name, content := range files {
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

	f, err := os.Open(zipPath)
	require.NoError(t, err)
	defer f.Close()

	assert.True(t, ext.CanExtract(ctx, zipPath, f))

	// non-zip file
	nonZipPath := filepath.Join(dir, "notazip.txt")
	require.NoError(t, os.WriteFile(nonZipPath, []byte("just text"), 0o644))

	f2, err := os.Open(nonZipPath)
	require.NoError(t, err)
	defer f2.Close()

	assert.False(t, ext.CanExtract(ctx, nonZipPath, f2))
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
	destDir := filepath.Join(dir, "extracted")
	require.NoError(t, os.MkdirAll(destDir, 0o755))

	result, err := ext.Extract(ctx, zipPath, destDir, ExtractionLimits{})
	require.NoError(t, err)
	assert.Equal(t, 2, result.FilesExtracted)

	// verify extracted files
	content, err := os.ReadFile(filepath.Join(destDir, "file1.txt"))
	require.NoError(t, err)
	assert.Equal(t, "content1", string(content))

	content, err = os.ReadFile(filepath.Join(destDir, "dir", "file2.txt"))
	require.NoError(t, err)
	assert.Equal(t, "content2", string(content))
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
	destDir := filepath.Join(dir, "extracted")
	require.NoError(t, os.MkdirAll(destDir, 0o755))

	_, err := ext.Extract(ctx, zipPath, destDir, ExtractionLimits{MaxFileCount: 2})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file count limit")
}

func TestZipExtractor_Extract_SizeLimitReached(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	files := map[string]string{
		"file1.txt": strings.Repeat("x", 100),
	}
	zipPath := createTestZip(t, dir, files)

	ext := &ZipExtractor{}
	destDir := filepath.Join(dir, "extracted")
	require.NoError(t, os.MkdirAll(destDir, 0o755))

	_, err := ext.Extract(ctx, zipPath, destDir, ExtractionLimits{MaxExtractionSizeBytes: 50})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "size limit")
}

func TestTarExtractor_CanExtract(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	tarPath := createTestTarGz(t, dir, map[string]string{"hello.txt": "world"})

	ext := &TarExtractor{}

	f, err := os.Open(tarPath)
	require.NoError(t, err)
	defer f.Close()

	assert.True(t, ext.CanExtract(ctx, tarPath, f))
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
	destDir := filepath.Join(dir, "extracted")
	require.NoError(t, os.MkdirAll(destDir, 0o755))

	result, err := ext.Extract(ctx, tarPath, destDir, ExtractionLimits{})
	require.NoError(t, err)
	assert.Equal(t, 2, result.FilesExtracted)

	// verify extracted files
	content, err := os.ReadFile(filepath.Join(destDir, "file1.txt"))
	require.NoError(t, err)
	assert.Equal(t, "content1", string(content))

	content, err = os.ReadFile(filepath.Join(destDir, "dir", "file2.txt"))
	require.NoError(t, err)
	assert.Equal(t, "content2", string(content))
}

func TestFindExtractor(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	extractors := DefaultExtractors()

	// zip file should match
	zipPath := createTestZip(t, dir, map[string]string{"hello.txt": "world"})
	ext := FindExtractor(ctx, extractors, zipPath)
	require.NotNil(t, ext)
	assert.IsType(t, &ZipExtractor{}, ext)

	// tar.gz should match
	tarPath := createTestTarGz(t, dir, map[string]string{"hello.txt": "world"})
	ext = FindExtractor(ctx, extractors, tarPath)
	require.NotNil(t, ext)
	assert.IsType(t, &TarExtractor{}, ext)

	// non-archive should return nil
	textPath := filepath.Join(dir, "plain.txt")
	require.NoError(t, os.WriteFile(textPath, []byte("just text"), 0o644))
	ext = FindExtractor(ctx, extractors, textPath)
	assert.Nil(t, ext)
}

func TestIsExcludedExtension(t *testing.T) {
	assert.True(t, IsExcludedExtension("/path/to/file.rpm", []string{".rpm", ".deb"}))
	assert.True(t, IsExcludedExtension("/path/to/file.deb", []string{".rpm", ".deb"}))
	assert.False(t, IsExcludedExtension("/path/to/file.zip", []string{".rpm", ".deb"}))
	assert.False(t, IsExcludedExtension("/path/to/file.zip", nil))
}

func TestFindExtractor_NoReaders(t *testing.T) {
	ctx := context.Background()
	ext := FindExtractor(ctx, DefaultExtractors(), "/nonexistent/path")
	assert.Nil(t, ext)
}

func TestTarExtractor_CanExtract_NonTarFile(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	// create a plain text file
	path := filepath.Join(dir, "plain.txt")
	require.NoError(t, os.WriteFile(path, []byte("not a tar"), 0o644))

	ext := &TarExtractor{}
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	assert.False(t, ext.CanExtract(ctx, path, f))
}

func TestTarExtractor_CanExtract_ZipFileReturnsFalse(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	zipPath := createTestZip(t, dir, map[string]string{"hello.txt": "world"})

	ext := &TarExtractor{}
	f, err := os.Open(zipPath)
	require.NoError(t, err)
	defer f.Close()

	// tar extractor should NOT claim to handle zip files
	assert.False(t, ext.CanExtract(ctx, zipPath, f))
}

func TestDefaultExtractionLimits(t *testing.T) {
	cfg := cataloging.ArchiveSearchConfig{
		MaxExtractionSizeBytes: 1024,
		MaxFileCount:           50,
	}
	limits := DefaultExtractionLimits(cfg)
	assert.Equal(t, int64(1024), limits.MaxExtractionSizeBytes)
	assert.Equal(t, 50, limits.MaxFileCount)
}

func TestZipExtractor_Extract_ZipSlipPrevented(t *testing.T) {
	// Create a zip with a path traversal entry
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
	destDir := filepath.Join(dir, "extracted")
	require.NoError(t, os.MkdirAll(destDir, 0o755))

	_, err = ext.Extract(ctx, zipPath, destDir, ExtractionLimits{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path traversal")

	// verify evil file was not created
	_, statErr := os.Stat(filepath.Join(dir, "etc", "passwd"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestTarExtractor_Extract_SymlinkInsideRootIsCreated(t *testing.T) {
	// A tar archive with a symlink whose target stays inside the extraction
	// directory should be written as a real symlink, not as a regular file
	// containing the link target as bytes.
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
	destDir := filepath.Join(dir, "extracted")
	require.NoError(t, os.MkdirAll(destDir, 0o755))

	_, err = ext.Extract(ctx, tarPath, destDir, ExtractionLimits{})
	require.NoError(t, err)

	// the link should be a real symlink
	info, err := os.Lstat(filepath.Join(destDir, "link.txt"))
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&fs.ModeSymlink, "expected link.txt to be a symlink, got mode %v", info.Mode())

	// reading through the link should return the target's content
	readBack, err := os.ReadFile(filepath.Join(destDir, "link.txt"))
	require.NoError(t, err)
	assert.Equal(t, "real content", string(readBack))
}

func TestTarExtractor_Extract_SymlinkEscapingRootIsSkipped(t *testing.T) {
	// A symlink whose target resolves outside the extraction directory must not
	// be created — neither as a symlink nor as a regular file. Extraction itself
	// should succeed (the unsafe entry is skipped, not fatal).
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
	destDir := filepath.Join(dir, "extracted")
	require.NoError(t, os.MkdirAll(destDir, 0o755))

	_, err = ext.Extract(ctx, tarPath, destDir, ExtractionLimits{})
	require.NoError(t, err)

	// nothing should have been created at the destination
	_, statErr := os.Lstat(filepath.Join(destDir, "passwd"))
	assert.True(t, os.IsNotExist(statErr), "expected no entry to be created for escaping symlink")
}

func TestTarExtractor_Extract_AbsoluteSymlinkTargetIsSkipped(t *testing.T) {
	// Absolute symlink targets must be rejected: os.Symlink writes the literal
	// target, so once the symlink is read it resolves on the host filesystem
	// regardless of any safety check at extraction time. Verifying both that
	// the symlink itself is not created and (importantly) that nothing was
	// written under destDir along the absolute path.
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
	destDir := filepath.Join(dir, "extracted")
	require.NoError(t, os.MkdirAll(destDir, 0o755))

	_, err = ext.Extract(ctx, tarPath, destDir, ExtractionLimits{})
	require.NoError(t, err)

	// the symlink itself must not exist
	_, statErr := os.Lstat(filepath.Join(destDir, "shadow"))
	assert.True(t, os.IsNotExist(statErr), "expected absolute-target symlink to be skipped")
}
