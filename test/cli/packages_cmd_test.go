package cli

import (
	"strings"
	"testing"

	"github.com/anchore/syft/syft/source"
)

func TestPackagesCmdFlags(t *testing.T) {
	request := "docker-archive:" + getFixtureImage(t, "image-pkg-coverage")

	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			name: "json-output-flag",
			args: []string{"packages", "-o", "json", request},
			assertions: []traitAssertion{
				assertJsonReport,
				assertSource(source.SquashedScope),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "output-env-binding",
			env: map[string]string{
				"SYFT_OUTPUT": "json",
			},
			args: []string{"packages", request},
			assertions: []traitAssertion{
				assertJsonReport,
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "table-output-flag",
			args: []string{"packages", "-o", "table", request},
			assertions: []traitAssertion{
				assertTableReport,
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "default-output-flag",
			args: []string{"packages", request},
			assertions: []traitAssertion{
				assertTableReport,
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "squashed-scope-flag",
			args: []string{"packages", "-o", "json", "-s", "squashed", request},
			assertions: []traitAssertion{
				assertSource(source.SquashedScope),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "all-layers-scope-flag",
			args: []string{"packages", "-o", "json", "-s", "all-layers", request},
			assertions: []traitAssertion{
				assertSource(source.AllLayersScope),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "packages-scope-env-binding",
			env: map[string]string{
				"SYFT_PACKAGES_SCOPE": "all-layers",
			},
			args: []string{"packages", "-o", "json", request},
			assertions: []traitAssertion{
				assertSource(source.AllLayersScope),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "attempt-upload-on-cli-switches",
			args: []string{"packages", "-vv", "-H", "localhost:8080", "-u", "the-username", "-d", "test-fixtures/image-pkg-coverage/Dockerfile", "--overwrite-existing-image", request},
			env: map[string]string{
				"SYFT_ANCHORE_PATH":     "path/to/api",
				"SYFT_ANCHORE_PASSWORD": "the-password",
			},
			assertions: []traitAssertion{
				// we cannot easily assert a successful upload behavior, so instead we are doing the next best thing
				// and asserting that the parsed configuration has the expected values and we see log entries
				// indicating an upload attempt.
				assertNotInOutput("the-username"),
				assertNotInOutput("the-password"),
				assertInOutput("uploading results to localhost:8080"),
				assertInOutput(`dockerfile: test-fixtures/image-pkg-coverage/Dockerfile`),
				assertInOutput(`overwrite-existing-image: true`),
				assertInOutput(`path: path/to/api`),
				assertInOutput(`host: localhost:8080`),
				assertFailingReturnCode, // upload can't go anywhere, so if this passes that would be surprising
			},
		},
		{
			name: "dockerfile-without-upload-is-invalid",
			args: []string{"packages", "-vv", "-d", "test-fixtures/image-pkg-coverage/Dockerfile", request},
			assertions: []traitAssertion{

				assertNotInOutput("uploading results to localhost:8080"),
				assertInOutput("invalid application config: cannot provide dockerfile option without enabling upload"),
				assertFailingReturnCode,
			},
		},
		{
			name: "attempt-upload-with-env-host-set",
			args: []string{"packages", "-vv", request},
			env: map[string]string{
				"SYFT_ANCHORE_HOST": "localhost:8080",
			},
			assertions: []traitAssertion{
				assertInOutput("uploading results to localhost:8080"),
				assertFailingReturnCode, // upload can't go anywhere, so if this passes that would be surprising
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
