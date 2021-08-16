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
			name: "no-args-shows-help",
			args: []string{"packages"},
			assertions: []traitAssertion{
				assertInOutput("an image/directory argument is required"),              // specific error that should be shown
				assertInOutput("Generate a packaged-based Software Bill Of Materials"), // excerpt from help description
				assertFailingReturnCode,
			},
		},
		{
			name: "json-output-flag",
			args: []string{"packages", "-o", "json", request},
			assertions: []traitAssertion{
				assertJsonReport,
				assertScope(source.SquashedScope),
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
				assertScope(source.SquashedScope),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "all-layers-scope-flag",
			args: []string{"packages", "-o", "json", "-s", "all-layers", request},
			assertions: []traitAssertion{
				assertScope(source.AllLayersScope),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "packages-scope-env-binding",
			env: map[string]string{
				"SYFT_PACKAGE_CATALOGER_SCOPE": "all-layers",
			},
			args: []string{"packages", "-o", "json", request},
			assertions: []traitAssertion{
				assertScope(source.AllLayersScope),
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

func TestRegistryAuth(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			name: "fallback to keychain",
			args: []string{"packages", "-vv", "registry:localhost:5000/something:latest"},
			assertions: []traitAssertion{
				assertInOutput("source=OciRegistry"),
				assertInOutput("localhost:5000/something:latest"),
				assertInOutput("no registry credentials configured, using the default keychain"),
			},
		},
		{
			name: "use creds",
			args: []string{"packages", "-vv", "registry:localhost:5000/something:latest"},
			env: map[string]string{
				"SYFT_REGISTRY_AUTH_AUTHORITY": "localhost:5000",
				"SYFT_REGISTRY_AUTH_USERNAME":  "username",
				"SYFT_REGISTRY_AUTH_PASSWORD":  "password",
			},
			assertions: []traitAssertion{
				assertInOutput("source=OciRegistry"),
				assertInOutput("localhost:5000/something:latest"),
				assertInOutput(`using basic auth for registry "localhost:5000"`),
			},
		},
		{
			name: "use token",
			args: []string{"packages", "-vv", "registry:localhost:5000/something:latest"},
			env: map[string]string{
				"SYFT_REGISTRY_AUTH_AUTHORITY": "localhost:5000",
				"SYFT_REGISTRY_AUTH_TOKEN":     "token",
			},
			assertions: []traitAssertion{
				assertInOutput("source=OciRegistry"),
				assertInOutput("localhost:5000/something:latest"),
				assertInOutput(`using token for registry "localhost:5000"`),
			},
		},
		{
			name: "not enough info fallsback to keychain",
			args: []string{"packages", "-vv", "registry:localhost:5000/something:latest"},
			env: map[string]string{
				"SYFT_REGISTRY_AUTH_AUTHORITY": "localhost:5000",
			},
			assertions: []traitAssertion{
				assertInOutput("source=OciRegistry"),
				assertInOutput("localhost:5000/something:latest"),
				assertInOutput(`no registry credentials configured, using the default keychain`),
			},
		},
		{
			name: "allows insecure http flag",
			args: []string{"packages", "-vv", "registry:localhost:5000/something:latest"},
			env: map[string]string{
				"SYFT_REGISTRY_INSECURE_USE_HTTP": "true",
			},
			assertions: []traitAssertion{
				assertInOutput("insecure-use-http: true"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd, stdout, stderr := runSyft(t, test.env, test.args...)
			for _, traitAssertionFn := range test.assertions {
				traitAssertionFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}
			if t.Failed() {
				t.Log("STDOUT:\n", stdout)
				t.Log("STDERR:\n", stderr)
				t.Log("COMMAND:", strings.Join(cmd.Args, " "))
			}
		})
	}
}
