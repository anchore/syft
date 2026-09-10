package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/tmpdir"
	"github.com/anchore/syft/syft/file"
)

func TestExtractToResolver_writesUnderTheScansTempRoot(t *testing.T) {
	// where an archive's scratch space lands is the scan's decision, not this package's: the root on
	// the context is what a caller configured and what gets cleaned up if an archive's own cleanup is
	// ever missed. Reaching for os.MkdirTemp instead put archive work outside all of that.
	root := t.TempDir()
	ctx := tmpdir.WithValue(context.Background(), tmpdir.FromPath(root))

	var got Overflow
	factory := func(overflow Overflow) (file.Resolver, IndexResult, error) {
		got = overflow
		return nil, IndexResult{Records: 1}, nil
	}

	extracted, err := ExtractToResolver(
		ctx, newTestZip(t, map[string]string{"hello.txt": "hi"}), "app.zip", "", "app.zip",
		DefaultExtractors(), nil, ExtractionLimits{}, factory, nil, nil,
	)
	require.NoError(t, err)
	require.NotNil(t, extracted)
	t.Cleanup(extracted.Cleanup)

	assert.True(t, strings.HasPrefix(got.TarPath, root+string(os.PathSeparator)),
		"the archive's entries must be written under the scan's temp root, got %q", got.TarPath)

	// and the archive still cleans up after itself, so the root is a safety net rather than the only
	// thing reclaiming the space
	extracted.Cleanup()
	_, statErr := os.Stat(got.RootDir)
	assert.True(t, os.IsNotExist(statErr), "expected the archive work directory to be removed by Cleanup")
}

func TestExtractToResolver(t *testing.T) {
	content := newTestZip(t, map[string]string{"dir/hello.txt": "hello world"})

	var got Overflow
	factory := func(overflow Overflow) (file.Resolver, IndexResult, error) {
		got = overflow
		return nil, IndexResult{Records: 1}, nil
	}

	extracted, err := ExtractToResolver(
		context.Background(), content, "some/path/app.zip", "parentFS", "app.war:some/path/app.zip",
		DefaultExtractors(), nil, ExtractionLimits{}, factory, nil, nil,
	)
	require.NoError(t, err)
	require.NotNil(t, extracted)
	t.Cleanup(extracted.Cleanup)

	// the filesystem the archive lives on is passed through unchanged; the nesting chain is carried
	// separately as the archive path, and both are handed to the resolver factory
	assert.Equal(t, "parentFS", extracted.FileSystemID)
	assert.Equal(t, "parentFS", got.FileSystemID)
	assert.Equal(t, "app.war:some/path/app.zip", extracted.ArchivePath)
	assert.Equal(t, "app.war:some/path/app.zip", got.ArchivePath)

	// the archive's entries are in the one tar handed to the factory, and its logical root is an
	// empty directory beside it: an entry's path is reported relative to that root, and nothing is
	// written into it
	entries, err := os.ReadDir(got.RootDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "the archive root holds no files: the entries are in the tar")

	body := readTarEntry(t, got.TarPath, "dir/hello.txt")
	assert.Equal(t, "hello world", body)

	// the count of entries this archive contributes is the index's answer, not the extractor's
	assert.Equal(t, 1, extracted.Result.FilesExtracted)

	// Cleanup removes the temp tree
	extracted.Cleanup()
	_, statErr := os.Stat(got.TarPath)
	assert.True(t, os.IsNotExist(statErr), "expected the overflow tar to be removed by Cleanup")
	_, statErr = os.Stat(got.RootDir)
	assert.True(t, os.IsNotExist(statErr), "expected temp dir to be removed by Cleanup")
}

// readTarEntry returns the content of one entry of a tar on disk.
func readTarEntry(t *testing.T, tarPath, name string) string {
	t.Helper()
	f, err := os.Open(tarPath)
	require.NoError(t, err)
	defer f.Close()

	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		if hdr.Name != name {
			continue
		}
		body, err := io.ReadAll(tr)
		require.NoError(t, err)
		return string(body)
	}
	t.Fatalf("no entry %q in %q", name, tarPath)
	return ""
}

func TestExtractToResolver_notAnArchive(t *testing.T) {
	factory := func(Overflow) (file.Resolver, IndexResult, error) { return nil, IndexResult{}, nil }

	extracted, err := ExtractToResolver(
		context.Background(), strings.NewReader("this is not an archive"), "notes.txt", "", "notes.txt",
		DefaultExtractors(), nil, ExtractionLimits{}, factory, nil, nil,
	)
	require.NoError(t, err)
	assert.Nil(t, extracted, "non-archive content should yield a nil ExtractedArchive")
}

func newTestZip(t *testing.T, files map[string]string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return &buf
}
