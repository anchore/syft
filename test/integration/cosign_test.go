package integration

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runAndShow(t *testing.T, cmd *exec.Cmd) {
	t.Helper()

	stderr, err := cmd.StderrPipe()
	require.NoErrorf(t, err, "could not get stderr: +v", err)

	stdout, err := cmd.StdoutPipe()
	require.NoErrorf(t, err, "could not get stdout: +v", err)

	err = cmd.Start()
	require.NoErrorf(t, err, "failed to start cmd: %+v", err)

	show := func(label string, reader io.ReadCloser) {
		scanner := bufio.NewScanner(reader)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			t.Logf("%s: %s", label, scanner.Text())
		}
	}

	show("out", stdout)
	show("err", stderr)
}

func TestCosignWorkflow(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*testing.T)
		cleanup func()
	}{
		{
			name: "cosign verify syft attest",
			setup: func(t *testing.T) {
				cwd, err := os.Getwd()
				require.NoErrorf(t, err, "unable to get cwd: %+v", err)

				// get working directory for local registry
				fixturesPath := filepath.Join(cwd, "test-fixtures", "registry")
				makeTask := filepath.Join(fixturesPath, "Makefile")
				t.Logf("Generating Fixture from 'make %s'", makeTask)

				cmd := exec.Command("make")
				cmd.Dir = fixturesPath
				runAndShow(t, cmd)

				// TODO Load Image

				time.Sleep(time.Second) // TODO: sync so test starts when registry is ready
			},
			cleanup: func() {
				cwd, err := os.Getwd()
				assert.NoErrorf(t, err, "unable to get cwd: %+v", err)
				err = os.Unsetenv("CONTAINER_HOST")
				assert.NoError(t, err)
				err = os.Unsetenv("CONTAINER_SSHKEY")
				assert.NoError(t, err)

				fixturesPath := filepath.Join(cwd, "test-fixtures", "registry")
				makeTask := filepath.Join(fixturesPath, "Makefile")
				t.Logf("Generating Fixture from 'make %s'", makeTask)

				cmd := exec.Command("make", "stop")
				cmd.Dir = fixturesPath

				runAndShow(t, cmd)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(tt.cleanup)

			tt.setup(t)
		})
	}
}
