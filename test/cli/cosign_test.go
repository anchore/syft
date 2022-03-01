package cli

import (
	"bufio"
	"io"
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
	coverageImage := "localhost:2222/attest:latest"
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
				coverageImage,
			},
			// cosign attach attestation --attestation image_latest_sbom_attestation.json caphill4/attest:latest
			cosignAttachArgs: []string{
				"attach",
				"attestation",
				"--attestation",
				attestationFile,
				coverageImage,
			},
			// cosign verify-attestation -key cosign.pub caphill4/attest:latest
			cosignVerifyArgs: []string{
				"verify-attestation",
				"-key",
				"cosign.pub",
				coverageImage,
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

				time.Sleep(time.Second) // TODO: sync so test starts when registry is ready
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
			os.WriteFile("attestation.json", []byte(stdout), 0666)

			// attach
			cmd, stdout, stderr = runCosign(t, tt.env, tt.cosignAttachArgs...)
			for _, traitFn := range tt.assertions {
				traitFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}

			// attest
			cmd, stdout, stderr = runCosign(t, tt.env, tt.cosignAttachArgs...)
			for _, traitFn := range tt.assertions {
				traitFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}
			if t.Failed() {
				t.Log("STDOUT:\n", stdout)
				t.Log("STDERR:\n", stderr)
				t.Log("COMMAND:", strings.Join(cmd.Args, " "))
			}
		})
	}
}
