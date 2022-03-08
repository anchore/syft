package cli

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackagesCmdFlags(t *testing.T) {
	coverageImage := "docker-archive:" + getFixtureImage(t, "image-pkg-coverage")
	//badBinariesImage := "docker-archive:" + getFixtureImage(t, "image-bad-binaries")
	tmp := t.TempDir() + "/"

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
			args: []string{"packages", "-o", "json", coverageImage},
			assertions: []traitAssertion{
				assertJsonReport,
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "multiple-output-flags",
			args: []string{"packages", "-o", "table", "-o", "json=" + tmp + ".tmp/multiple-output-flag-test.json", coverageImage},
			assertions: []traitAssertion{
				assertTableReport,
				assertFileExists(tmp + ".tmp/multiple-output-flag-test.json"),
				assertSuccessfulReturnCode,
			},
		},
		// I haven't been able to reproduce locally yet, but in CI this has proven to be unstable:
		// For the same commit:
		//   pass: https://github.com/anchore/syft/runs/4611344142?check_suite_focus=true
		//   fail: https://github.com/anchore/syft/runs/4611343586?check_suite_focus=true
		// For the meantime this test will be commented out, but should be added back in as soon as possible.
		//
		//{
		//	name: "regression-survive-bad-binaries",
		//	// this image has all sorts of rich binaries from the clang-13 test suite that should do pretty bad things
		//	// to the go cataloger binary path. We should NEVER let a panic stop the cataloging process for these
		//	// specific cases.
		//
		//	// this is more of an integration test, however, to assert the output we want to see from the application
		//	// a CLI test is much easier.
		//	args: []string{"packages", "-vv", badBinariesImage},
		//	assertions: []traitAssertion{
		//		assertInOutput("could not parse possible go binary"),
		//		assertSuccessfulReturnCode,
		//	},
		//},
		{
			name: "output-env-binding",
			env: map[string]string{
				"SYFT_OUTPUT": "json",
			},
			args: []string{"packages", coverageImage},
			assertions: []traitAssertion{
				assertJsonReport,
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "table-output-flag",
			args: []string{"packages", "-o", "table", coverageImage},
			assertions: []traitAssertion{
				assertTableReport,
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "default-output-flag",
			args: []string{"packages", coverageImage},
			assertions: []traitAssertion{
				assertTableReport,
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "squashed-scope-flag",
			args: []string{"packages", "-o", "json", "-s", "squashed", coverageImage},
			assertions: []traitAssertion{
				assertPackageCount(20),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "all-layers-scope-flag",
			args: []string{"packages", "-o", "json", "-s", "all-layers", coverageImage},
			assertions: []traitAssertion{
				assertPackageCount(22),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "all-layers-scope-flag-by-env",
			args: []string{"packages", "-o", "json", coverageImage},
			env: map[string]string{
				"SYFT_PACKAGE_CATALOGER_SCOPE": "all-layers",
			},
			assertions: []traitAssertion{
				assertPackageCount(22),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "attempt-upload-on-cli-switches",
			args: []string{"packages", "-vv", "-H", "localhost:8080", "-u", "the-username", "-d", "test-fixtures/image-pkg-coverage/Dockerfile", "--overwrite-existing-image", coverageImage},
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
			args: []string{"packages", "-vv", "-d", "test-fixtures/image-pkg-coverage/Dockerfile", coverageImage},
			assertions: []traitAssertion{

				assertNotInOutput("uploading results to localhost:8080"),
				assertInOutput("invalid application config: cannot provide dockerfile option without enabling upload"),
				assertFailingReturnCode,
			},
		},
		{
			name: "attempt-upload-with-env-host-set",
			args: []string{"packages", "-vv", coverageImage},
			env: map[string]string{
				"SYFT_ANCHORE_HOST": "localhost:8080",
			},
			assertions: []traitAssertion{
				assertInOutput("uploading results to localhost:8080"),
				assertFailingReturnCode, // upload can't go anywhere, so if this passes that would be surprising
			},
		},
		{
			// we want to make certain that syft can catalog a single go binary and get a SBOM report that is not empty
			name: "catalog-single-go-binary",
			args: []string{"packages", "-o", "json", getSyftBinaryLocation(t)},
			assertions: []traitAssertion{
				assertJsonReport,
				assertStdoutLengthGreaterThan(1000),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "responds-to-package-cataloger-search-options",
			args: []string{"packages", "-vv"},
			env: map[string]string{
				"SYFT_PACKAGE_SEARCH_UNINDEXED_ARCHIVES": "true",
				"SYFT_PACKAGE_SEARCH_INDEXED_ARCHIVES":   "false",
			},
			assertions: []traitAssertion{
				// the application config in the log matches that of what we expect to have been configured. Note:
				// we are not testing further wiring of this option, only that the config responds to
				// package-cataloger-level options.
				assertInOutput("search-unindexed-archives: true"),
				assertInOutput("search-indexed-archives: false"),
			},
		},
		{
			name: "platform-option-wired-up",
			args: []string{"packages", "--platform", "arm64", "-o", "json", "registry:busybox:1.31"},
			assertions: []traitAssertion{
				assertInOutput("sha256:1ee006886991ad4689838d3a288e0dd3fd29b70e276622f16b67a8922831a853"), // linux/arm64 image digest
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "json-file-flag",
			args: []string{"packages", "-o", "json", "--file", filepath.Join(tmp, "output-1.json"), coverageImage},
			assertions: []traitAssertion{
				assertSuccessfulReturnCode,
				assertFileOutput(t, filepath.Join(tmp, "output-1.json"),
					assertJsonReport,
				),
			},
		},
		{
			name: "json-output-flag-to-file",
			args: []string{"packages", "-o", fmt.Sprintf("json=%s", filepath.Join(tmp, "output-2.json")), coverageImage},
			assertions: []traitAssertion{
				assertSuccessfulReturnCode,
				assertFileOutput(t, filepath.Join(tmp, "output-2.json"),
					assertJsonReport,
				),
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
	host := "localhost:17"
	image := fmt.Sprintf("%s/something:latest", host)
	args := []string{"packages", "-vv", fmt.Sprintf("registry:%s", image)}

	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			name: "fallback to keychain",
			args: args,
			assertions: []traitAssertion{
				assertInOutput("source=OciRegistry"),
				assertInOutput(image),
				assertInOutput("no registry credentials configured, using the default keychain"),
			},
		},
		{
			name: "use creds",
			args: args,
			env: map[string]string{
				"SYFT_REGISTRY_AUTH_AUTHORITY": host,
				"SYFT_REGISTRY_AUTH_USERNAME":  "username",
				"SYFT_REGISTRY_AUTH_PASSWORD":  "password",
			},
			assertions: []traitAssertion{
				assertInOutput("source=OciRegistry"),
				assertInOutput(image),
				assertInOutput(fmt.Sprintf(`using basic auth for registry "%s"`, host)),
			},
		},
		{
			name: "use token",
			args: args,
			env: map[string]string{
				"SYFT_REGISTRY_AUTH_AUTHORITY": host,
				"SYFT_REGISTRY_AUTH_TOKEN":     "token",
			},
			assertions: []traitAssertion{
				assertInOutput("source=OciRegistry"),
				assertInOutput(image),
				assertInOutput(fmt.Sprintf(`using token for registry "%s"`, host)),
			},
		},
		{
			name: "not enough info fallsback to keychain",
			args: args,
			env: map[string]string{
				"SYFT_REGISTRY_AUTH_AUTHORITY": host,
			},
			assertions: []traitAssertion{
				assertInOutput("source=OciRegistry"),
				assertInOutput(image),
				assertInOutput(`no registry credentials configured, using the default keychain`),
			},
		},
		{
			name: "allows insecure http flag",
			args: args,
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
