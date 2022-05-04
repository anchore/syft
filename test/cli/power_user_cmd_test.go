package cli

import (
	"strings"
	"testing"
)

func TestPowerUserCmdFlags(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			name: "no-args-shows-help",
			args: []string{"power-user"},
			assertions: []traitAssertion{
				assertInOutput("an image/directory argument is required"), // specific error that should be shown
				assertInOutput("Run bulk operations on container images"), // excerpt from help description
				assertFailingReturnCode,
			},
		},
		{
			name: "default-results-w-pkg-coverage",
			args: []string{"power-user", "docker-archive:" + getFixtureImage(t, "image-pkg-coverage"), "-vv"},
			assertions: []traitAssertion{
				assertNotInOutput(" command is deprecated"),     // only the root command should be deprecated
				assertInOutput(`"type": "RegularFile"`),         // proof of file-metadata data
				assertInOutput(`"algorithm": "sha256"`),         // proof of file-metadata default digest algorithm of sha256
				assertInOutput(`"metadataType": "ApkMetadata"`), // proof of package artifacts data
				assertSuccessfulReturnCode,
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
