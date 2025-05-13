package cli

import (
	"testing"
)

func Test_Unknowns(t *testing.T) {
	unknownsImage := getFixtureImage(t, "image-unknowns")

	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			name: "unknown executables",
			args: []string{"scan", "-o", "json", unknownsImage, "--from", "docker-archive"},
			env:  map[string]string{"SYFT_FORMAT_PRETTY": "true"},
			assertions: []traitAssertion{
				assertJsonReport,
				assertInOutput(`no package identified in executable file`),
				assertInOutput(`unable to read files from java archive`),
				assertInOutput(`no package identified in archive`),
				assertInOutput(`cycle during symlink resolution`),
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
			logOutputOnFailure(t, cmd, stdout, stderr)
		})
	}
}
