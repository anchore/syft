package cli

import (
	"strings"
	"testing"
)

func TestAttestCmdFlags(t *testing.T) {
	// coverageImage := "docker-archive:" + getFixtureImage(t, "image-pkg-coverage")
	// tmp := t.TempDir() + "/"

	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			name: "no-args-shows-help",
			args: []string{"attest"},
			assertions: []traitAssertion{
				assertInOutput("an image/directory argument is required"),              // specific error that should be shown
				assertInOutput("Generate a packaged-based Software Bill Of Materials"), // excerpt from help description
				assertFailingReturnCode,
			},
		},
		{
			name: "can pass a key password during run OR as ENVVAR",
			args: []string{"attest"},
			assertions: []traitAssertion{
				assertInOutput("an image/directory argument is required"),              // specific error that should be shown
				assertInOutput("Generate a packaged-based Software Bill Of Materials"), // excerpt from help description
				assertFailingReturnCode,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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
