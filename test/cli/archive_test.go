package cli

import (
	"archive/tar"
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
				"file:" + createArchive(t, "test-fixtures/archive", t.TempDir()),
			},
			assertions: []traitAssertion{
				assertSuccessfulReturnCode,
				assertJsonReport,
				assertPackageCount(1),
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
