package cli

import (
	"strings"
	"testing"
)

func TestAttestCmd(t *testing.T) {
	img := "registry:busybox:latest"
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
				assertInOutput("an image/directory argument is required"),                           // specific error that should be shown
				assertInOutput("from a container image as the predicate of an in-toto attestation"), // excerpt from help description
				assertFailingReturnCode,
			},
			pw: "",
		},
		{
			name: "can encode syft.json as the predicate given a password",
			args: []string{"attest", "-o", "json", "--key", "cosign.key", img},
			assertions: []traitAssertion{
				assertSuccessfulReturnCode,
			},
			pw: "test",
		},
		{
			name: "can encode syft.json as the predicate given a blank password",
			args: []string{"attest", "-o", "json", "--key", "cosign.key", img},
			assertions: []traitAssertion{
				assertSuccessfulReturnCode,
			},
			pw: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cleanup := setupPKI(t, test.pw)
			defer cleanup()
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
