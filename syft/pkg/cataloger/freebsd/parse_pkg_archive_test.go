package freebsd

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func TestPkgManifest_ToEntry(t *testing.T) {
	m := pkgManifest{
		Name:    "curl",
		Origin:  "www/curl",
		Version: "8.9.1",
		Abi:     "FreeBSD:14:amd64",
		Files: map[string]pkgManifestFile{
			"/usr/local/share/doc/curl/FAQ": {Sum: "1$bbbb", UName: "root", GName: "wheel"},
			"/usr/local/bin/curl":           {Sum: "1$aaaa", UName: "root", GName: "wheel"},
		},
	}

	entry := m.toEntry()

	require.Len(t, entry.Files, 2)
	// files are sorted by path regardless of map iteration order
	assert.Equal(t, "/usr/local/bin/curl", entry.Files[0].Path)
	assert.Equal(t, "aaaa", entry.Files[0].Digest)
	assert.Equal(t, "/usr/local/share/doc/curl/FAQ", entry.Files[1].Path)
	assert.Equal(t, "bbbb", entry.Files[1].Digest)
}

// createTestTarWithManifest builds an uncompressed in-memory tar containing a +MANIFEST entry.
func createTestTarWithManifest(t *testing.T, manifest string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: pkgManifestEntryName,
		Mode: 0644,
		Size: int64(len(manifest)),
	}))
	_, err := tw.Write([]byte(manifest))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	return buf.Bytes()
}

func TestParsePkgArchive_UncompressedTar(t *testing.T) {
	manifest := `{"name":"example","origin":"misc/example","version":"1.0.0","abi":"FreeBSD:14:amd64"}`
	tarBytes := createTestTarWithManifest(t, manifest)

	loc := file.NewLocation("example.pkg")
	reader := file.NewLocationReadCloser(loc, io.NopCloser(bytes.NewReader(tarBytes)))

	pkgs, relationships, err := parsePkgArchive(context.Background(), nil, nil, reader)
	require.NoError(t, err)
	assert.Empty(t, relationships)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "example", pkgs[0].Name)
	assert.Equal(t, "1.0.0", pkgs[0].Version)
	assert.Equal(t, pkg.FreeBSDPkg, pkgs[0].Type)
}

func TestParsePkgArchive_NoManifest(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "some-file", Mode: 0644, Size: 0}))
	require.NoError(t, tw.Close())

	loc := file.NewLocation("example.pkg")
	reader := file.NewLocationReadCloser(loc, io.NopCloser(bytes.NewReader(buf.Bytes())))

	_, _, err := parsePkgArchive(context.Background(), nil, nil, reader)
	require.Error(t, err)
}
