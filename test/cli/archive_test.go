package cli

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestArchiveScan(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		archiveFixture string
		env            map[string]string
		assertions     []traitAssertion
	}{
		{
			name: "scan an archive within the temp dir",
			args: []string{
				"scan",
				"-o",
				"json",
				"file:" + createArchive(t, "testdata/archive", t.TempDir()),
			},
			assertions: []traitAssertion{
				assertSuccessfulReturnCode,
				assertJsonReport,
				assertPackageCount(1),
			},
		},
		{
			// a Java resource adapter archive is a zip file with a .rar extension
			name: "scan a java resource adapter archive",
			args: []string{
				"scan",
				"-o",
				"json",
				"--from",
				"file",
				createResourceAdapterArchive(t, t.TempDir()),
			},
			assertions: []traitAssertion{
				assertSuccessfulReturnCode,
				assertJsonReport,
				assertInOutput("pkg:maven/org.example/example-ra@1.0.0"),
				assertInOutput("pkg:maven/org.example/example-lib@1.0.0"),
				assertPackageCount(2),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd, stdout, stderr := runSyft(t, test.env, test.args...)
			for _, traitAssertionFn := range test.assertions {
				traitAssertionFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}
			logOutputOnFailure(t, cmd, stdout, stderr)
		})
	}
}

func createArchive(t *testing.T, path string, destDir string) string {
	// create a tarball of the test fixtures (not by shelling out)
	archivePath := filepath.Join(destDir, "test.tar")

	fh, err := os.Create(archivePath)
	require.NoError(t, err)
	defer fh.Close()

	writer := tar.NewWriter(fh)
	require.NoError(t, writer.AddFS(os.DirFS(path)))
	require.NoError(t, writer.Close())

	return archivePath
}

// createResourceAdapterArchive writes a minimal Java resource adapter archive (a zip file with a .rar extension that
// holds a deployment descriptor and a nested jar) into destDir and returns its path.
func createResourceAdapterArchive(t *testing.T, destDir string) string {
	lib := zipBytes(t, [][2]string{
		{"META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n"},
		{"META-INF/maven/org.example/example-lib/pom.properties", "groupId=org.example\nartifactId=example-lib\nversion=1.0.0\n"},
	})

	ra := zipBytes(t, [][2]string{
		{"META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n"},
		{"META-INF/ra.xml", "<connector/>\n"},
		{"example-lib-1.0.0.jar", string(lib)},
		{"META-INF/maven/org.example/example-ra/pom.properties", "groupId=org.example\nartifactId=example-ra\nversion=1.0.0\n"},
	})

	archivePath := filepath.Join(destDir, "example-ra-1.0.0.rar")
	require.NoError(t, os.WriteFile(archivePath, ra, 0o600))
	return archivePath
}

// zipBytes returns a zip archive holding the given (name, contents) entries, in order.
func zipBytes(t *testing.T, entries [][2]string) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range entries {
		f, err := w.Create(e[0])
		require.NoError(t, err)
		_, err = f.Write([]byte(e[1]))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return buf.Bytes()
}
