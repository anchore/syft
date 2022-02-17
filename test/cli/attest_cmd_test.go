package cli

import (
	"os"
	"strings"
	"testing"
)

func TestAttestCmdFlags(t *testing.T) {
	coverageImage := "docker-archive:" + getFixtureImage(t, "image-pkg-coverage")
	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		assertions []traitAssertion
		pw         string
	}{
		{
			name: "no-args-shows-help",
			args: []string{"attest"},
			assertions: []traitAssertion{
				assertInOutput("an image/directory argument is required"),                   // specific error that should be shown
				assertInOutput("image or OCI directory as the predicate of an attestation"), // excerpt from help description
				assertFailingReturnCode,
			},
			pw: "",
		},
		{
			name: "can encode syft.json as the predicate",
			args: []string{"attest", "-o", "json", coverageImage},
			assertions: []traitAssertion{
				assertSuccessfulReturnCode,
				// assertVerifyAttestation(coverageImage), Follow up on this assertion with verify blog or ephemperal registry
			},
			pw: "test",
		},
		{
			name: "does not prompt for a password when pw is empty",
			args: []string{"attest", "-o", "json", coverageImage},
			assertions: []traitAssertion{
				assertSuccessfulReturnCode,
				// assertVerifyAttestation(coverageImage), Follow up on this assertion with verify blog or ephemperal registry
			},
			pw: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cleanup := setupPKI(t, test.pw)
			defer cleanup()

			if test.pw == "" {
				// we want to make sure the command succeeds
				// when the password is blank and the env is unset
				os.Unsetenv("COSIGN_PASSWORD")
			}

			cmd, stdout, stderr := runSyft(t, test.env, test.args...)
			for _, traitFn := range test.assertions {
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
