package cli

import (
	"strings"
	"testing"
)

func TestPowerUserCmdFlags(t *testing.T) {
	request := "docker-archive:" + getFixtureImage(t, "image-pkg-coverage")

	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			name: "json-output-flag-fails",
			args: []string{"power-user", "-o", "json", request},
			assertions: []traitAssertion{
				assertFailingReturnCode,
			},
		},
		{
			name: "default-results",
			args: []string{"power-user", request},
			assertions: []traitAssertion{
				assertNotInOutput(" command is deprecated"),     // only the root command should be deprecated
				assertInOutput(`"type": "regularFile"`),         // proof of file-metadata data
				assertInOutput(`"algorithm": "sha256"`),         // proof of file-metadata default digest algorithm of sha256
				assertInOutput(`"metadataType": "ApkMetadata"`), // proof of package artifacts data
				assertSuccessfulReturnCode,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd, stdout, stderr := runSyftCommand(t, test.env, test.args...)
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
