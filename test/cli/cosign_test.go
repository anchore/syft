package cli

import (
	"bufio"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	// found under test-fixtures/registry/Makefile
	img := "localhost:5000/attest:latest"
	attestationFile := "attestation.json"
	tests := []struct {
		name             string
		syftArgs         []string
		cosignAttachArgs []string
		cosignVerifyArgs []string
		env              map[string]string
		assertions       []traitAssertion
		setup            func(*testing.T)
		cleanup          func()
	}{
		{
			name: "cosign verify syft attest",
			syftArgs: []string{
				"attest",
				"-o",
				"json",
				"--key",
				"cosign.key",
				img,
			},
			// cosign attach attestation
			cosignAttachArgs: []string{
				"attach",
				"attestation",
				"--attestation",
				attestationFile,
				img,
			},
			// cosign verify-attestation
			cosignVerifyArgs: []string{
				"verify-attestation",
				"-key",
				"cosign.pub",
				img,
			},
			assertions: []traitAssertion{
				assertSuccessfulReturnCode,
			},
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

				var done = make(chan struct{})
				defer close(done)
				for interval := range testRetryIntervals(done) {
					resp, err := http.Get("http://127.0.0.1:5000/v2/")
					if err != nil {
						t.Logf("waiting for registry err=%+v", err)
					} else {
						if resp.StatusCode == http.StatusOK {
							break
						}
						t.Logf("waiting for registry code=%+v", resp.StatusCode)
					}

					time.Sleep(interval)
				}

				cmd = exec.Command("make", "push")
				cmd.Dir = fixturesPath
				runAndShow(t, cmd)

			},
			cleanup: func() {
				cwd, err := os.Getwd()
				assert.NoErrorf(t, err, "unable to get cwd: %+v", err)

				fixturesPath := filepath.Join(cwd, "test-fixtures", "registry")
				makeTask := filepath.Join(fixturesPath, "Makefile")
				t.Logf("Generating Fixture from 'make %s'", makeTask)

				// delete attestation file
				os.Remove(attestationFile)

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
			pkiCleanup := setupPKI(t, "") // blank password
			defer pkiCleanup()

			// attest
			cmd, stdout, stderr := runSyft(t, tt.env, tt.syftArgs...)
			for _, traitFn := range tt.assertions {
				traitFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}
			checkCmdFailure(t, stdout, stderr, cmd)
			require.NoError(t, os.WriteFile(attestationFile, []byte(stdout), 0666))

			// attach
			cmd, stdout, stderr = runCosign(t, tt.env, tt.cosignAttachArgs...)
			for _, traitFn := range tt.assertions {
				traitFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}
			checkCmdFailure(t, stdout, stderr, cmd)

			// attest
			cmd, stdout, stderr = runCosign(t, tt.env, tt.cosignAttachArgs...)
			for _, traitFn := range tt.assertions {
				traitFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}
			checkCmdFailure(t, stdout, stderr, cmd)

		})
	}
}

func checkCmdFailure(t testing.TB, stdout, stderr string, cmd *exec.Cmd) {
	require.Falsef(t, t.Failed(), "%s %s trait assertion failed", cmd.Path, strings.Join(cmd.Args, " "))
	if t.Failed() {
		t.Log("STDOUT:\n", stdout)
		t.Log("STDERR:\n", stderr)
		t.Log("COMMAND:", strings.Join(cmd.Args, " "))
	}
}
