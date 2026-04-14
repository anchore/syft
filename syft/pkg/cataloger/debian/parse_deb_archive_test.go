package debian

import (
	"archive/tar"
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessControlTar(t *testing.T) {
	tarBytes := createTestTarWithControlFiles(t)

	metadata, err := processControlTar(io.NopCloser(bytes.NewReader(tarBytes)))

	require.NoError(t, err)
	require.NotNil(t, metadata)

	assert.Equal(t, "test-package", metadata.Package)
	assert.Equal(t, "1.0.0", metadata.Version)

	// md5sums should have been parsed into file records
	require.Len(t, metadata.Files, 1)
	assert.Equal(t, "/usr/bin/test-command", metadata.Files[0].Path)
	assert.Equal(t, "d41d8cd98f00b204e9800998ecf8427e", metadata.Files[0].Digest.Value)

	// conffiles should have marked config files
	assert.True(t, metadata.Files[0].IsConfigFile, "file listed in conffiles should be marked as config")
}

func TestProcessControlTar_ConfigFileMarking(t *testing.T) {
	// Create a tar where conffiles lists paths that overlap with md5sums entries
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	controlContent := "Package: test-package\nVersion: 1.0.0\nArchitecture: all\n"
	writeTarEntry(t, tw, "control", controlContent)

	md5Content := "d41d8cd98f00b204e9800998ecf8427e  usr/bin/test-command\n" +
		"d41d8cd98f00b204e9800998ecf8427e  etc/test/config.conf\n" +
		"d41d8cd98f00b204e9800998ecf8427e  usr/bin/other-command\n"
	writeTarEntry(t, tw, "md5sums", md5Content)

	conffilesContent := "/usr/bin/test-command\n/etc/test/config.conf\n"
	writeTarEntry(t, tw, "conffiles", conffilesContent)

	require.NoError(t, tw.Close())

	metadata, err := processControlTar(io.NopCloser(bytes.NewReader(buf.Bytes())))
	require.NoError(t, err)
	require.Len(t, metadata.Files, 3)

	assert.True(t, metadata.Files[0].IsConfigFile, "first file should be marked as config file")
	assert.True(t, metadata.Files[1].IsConfigFile, "second file should be marked as config file")
	assert.False(t, metadata.Files[2].IsConfigFile, "third file should not be marked as config file")
}

// createTestTarWithControlFiles creates a simple in-memory tar file with test control files
func createTestTarWithControlFiles(t *testing.T) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	controlContent := "Package: test-package\nVersion: 1.0.0\nArchitecture: all\nMaintainer: Test <test@example.com>\nDescription: Test package\n"
	writeTarEntry(t, tw, "control", controlContent)

	md5Content := "d41d8cd98f00b204e9800998ecf8427e  usr/bin/test-command\n"
	writeTarEntry(t, tw, "md5sums", md5Content)

	conffilesContent := "/usr/bin/test-command\n"
	writeTarEntry(t, tw, "conffiles", conffilesContent)

	require.NoError(t, tw.Close())
	return buf.Bytes()
}

func writeTarEntry(t *testing.T, tw *tar.Writer, name, content string) {
	t.Helper()
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: name,
		Mode: 0644,
		Size: int64(len(content)),
	}))
	_, err := tw.Write([]byte(content))
	require.NoError(t, err)
}
