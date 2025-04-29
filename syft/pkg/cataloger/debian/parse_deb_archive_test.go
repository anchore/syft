package debian

import (
	"archive/tar"
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func TestReadControlFiles(t *testing.T) {
	tarBytes := createTestTarWithControlFiles(t)

	tarReader := bytes.NewReader(tarBytes)
	reader := tar.NewReader(tarReader)

	controlFile, md5sums, conffiles, err := readControlFiles(reader)

	require.NoError(t, err)
	assert.NotNil(t, controlFile, "expected control file to be found")
	assert.NotNil(t, md5sums, "expected md5sums file to be found")
	assert.NotNil(t, conffiles, "expected conffiles file to be found")

	assert.Contains(t, string(controlFile), "Package: test-package")
	assert.Contains(t, string(md5sums), "d41d8cd98f00b204e9800998ecf8427e")
	assert.Contains(t, string(conffiles), "/etc/test")
}

// createTestTarWithControlFiles creates a simple in-memory tar file with test control files
func createTestTarWithControlFiles(t *testing.T) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Add control file
	controlContent := `Package: test-package
Version: 1.0.0
Architecture: all
Maintainer: Test <test@example.com>
Description: Test package
`
	err := tw.WriteHeader(&tar.Header{
		Name: "control",
		Mode: 0644,
		Size: int64(len(controlContent)),
	})
	require.NoError(t, err)
	_, err = tw.Write([]byte(controlContent))
	require.NoError(t, err)

	// Add md5sums file
	md5Content := "d41d8cd98f00b204e9800998ecf8427e  usr/bin/test-command\n"
	err = tw.WriteHeader(&tar.Header{
		Name: "md5sums",
		Mode: 0644,
		Size: int64(len(md5Content)),
	})
	require.NoError(t, err)
	_, err = tw.Write([]byte(md5Content))
	require.NoError(t, err)

	// Add conffiles file
	conffilesContent := "/etc/test/config.conf\n"
	err = tw.WriteHeader(&tar.Header{
		Name: "conffiles",
		Mode: 0644,
		Size: int64(len(conffilesContent)),
	})
	require.NoError(t, err)
	_, err = tw.Write([]byte(conffilesContent))
	require.NoError(t, err)

	// Close the tar writer
	err = tw.Close()
	require.NoError(t, err)

	return buf.Bytes()
}

func TestMarkConfigFiles(t *testing.T) {
	// Create test data
	conffilesContent := []byte("/usr/bin/test-command\n/etc/test/config.conf\n")

	files := []pkg.DpkgFileRecord{
		{
			Path: "/usr/bin/test-command",
			Digest: &file.Digest{
				Algorithm: "md5",
				Value:     "d41d8cd98f00b204e9800998ecf8427e",
			},
		},
		{
			Path: "/etc/test/config.conf",
			Digest: &file.Digest{
				Algorithm: "md5",
				Value:     "d41d8cd98f00b204e9800998ecf8427e",
			},
		},
		{
			Path: "/usr/bin/other-command",
			Digest: &file.Digest{
				Algorithm: "md5",
				Value:     "d41d8cd98f00b204e9800998ecf8427e",
			},
		},
	}

	markConfigFiles(conffilesContent, files)

	assert.True(t, files[0].IsConfigFile, "first file should be marked as config file")
	assert.True(t, files[1].IsConfigFile, "second file should be marked as config file")
	assert.False(t, files[2].IsConfigFile, "third file should not be marked as config file")
}

func TestParseControlFile(t *testing.T) {
	controlContent := `Package: test-package
Version: 1.2.3-4
Architecture: amd64
Maintainer: Test User <test@example.com>
Installed-Size: 1234
Depends: libc6, libtest
Description: This is a test package
 More description text
 And even more details
`

	metadata, err := parseControlFile(controlContent)

	require.NoError(t, err)
	assert.Equal(t, "test-package", metadata.Package)
	assert.Equal(t, "1.2.3-4", metadata.Version)
	assert.Equal(t, "amd64", metadata.Architecture)
	assert.Equal(t, "Test User <test@example.com>", metadata.Maintainer)
	assert.Equal(t, 1234, metadata.InstalledSize)
	assert.Contains(t, metadata.Description, "This is a test package")
	assert.Len(t, metadata.Depends, 2)
	assert.Contains(t, metadata.Depends, "libc6")
	assert.Contains(t, metadata.Depends, "libtest")
}
