package cli

import (
	"fmt"
	"path/filepath"
	"testing"
)

const (
	// this is the number of packages that should be found in the image-pkg-coverage fixture image
	// when analyzed with the squashed scope.
	coverageImageSquashedPackageCount = 24
)

func TestPackagesCmdFlags(t *testing.T) {
	hiddenPackagesImage := "docker-archive:" + getFixtureImage(t, "image-hidden-packages")
	coverageImage := "docker-archive:" + getFixtureImage(t, "image-pkg-coverage")
	nodeBinaryImage := "docker-archive:" + getFixtureImage(t, "image-node-binary")
	// badBinariesImage := "docker-archive:" + getFixtureImage(t, "image-bad-binaries")
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
			name: "quiet-flag-with-logger",
			args: []string{"packages", "-qvv", "-o", "json", coverageImage},
			assertions: []traitAssertion{
				assertJsonReport,
				assertNoStderr,
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "quiet-flag-with-tui",
			args: []string{"packages", "-q", "-o", "json", coverageImage},
			assertions: []traitAssertion{
				assertJsonReport,
				assertNoStderr,
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
		// {
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
		// },
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
				assertPackageCount(coverageImageSquashedPackageCount),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "squashed-scope-flag-hidden-packages",
			args: []string{"packages", "-o", "json", "-s", "squashed", hiddenPackagesImage},
			assertions: []traitAssertion{
				assertPackageCount(162),
				assertNotInOutput("vsftpd"), // hidden package
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "all-layers-scope-flag",
			args: []string{"packages", "-o", "json", "-s", "all-layers", hiddenPackagesImage},
			assertions: []traitAssertion{
				assertPackageCount(163), // packages are now deduplicated for this case
				assertInOutput("all-layers"),
				assertInOutput("vsftpd"), // hidden package
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "all-layers-scope-flag-by-env",
			args: []string{"packages", "-o", "json", hiddenPackagesImage},
			env: map[string]string{
				"SYFT_PACKAGE_CATALOGER_SCOPE": "all-layers",
			},
			assertions: []traitAssertion{
				assertPackageCount(163), // packages are now deduplicated for this case
				assertInOutput("all-layers"),
				assertInOutput("vsftpd"), // hidden package
				assertSuccessfulReturnCode,
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
			name: "catalog-node-js-binary",
			args: []string{"packages", "-o", "json", nodeBinaryImage},
			assertions: []traitAssertion{
				assertJsonReport,
				assertInOutput("node.js"),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "responds-to-package-cataloger-search-options",
			args: []string{"--help"},
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
		{
			name: "catalogers-option",
			// This will detect enable python-index-cataloger, python-package-cataloger and ruby-gemspec cataloger
			args: []string{"packages", "-o", "json", "--catalogers", "python,ruby-gemspec", coverageImage},
			assertions: []traitAssertion{
				assertPackageCount(13),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "override-default-parallelism",
			args: []string{"packages", "-vvv", "-o", "json", coverageImage},
			env: map[string]string{
				"SYFT_PARALLELISM": "2",
			},
			assertions: []traitAssertion{
				// the application config in the log matches that of what we expect to have been configured.
				assertInOutput("parallelism: 2"),
				assertInOutput("parallelism=2"),
				assertPackageCount(coverageImageSquashedPackageCount),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "default-parallelism",
			args: []string{"packages", "-vvv", "-o", "json", coverageImage},
			assertions: []traitAssertion{
				// the application config in the log matches that of what we expect to have been configured.
				assertInOutput("parallelism: 1"),
				assertInOutput("parallelism=1"),
				assertPackageCount(coverageImageSquashedPackageCount),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "password and key not in config output",
			args: []string{"packages", "-vvv", "-o", "json", coverageImage},
			env: map[string]string{
				"SYFT_ATTEST_PASSWORD": "secret_password",
				"SYFT_ATTEST_KEY":      "secret_key_path",
			},
			assertions: []traitAssertion{
				assertNotInOutput("secret_password"),
				assertNotInOutput("secret_key_path"),
				assertPackageCount(coverageImageSquashedPackageCount),
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

func TestRegistryAuth(t *testing.T) {
	host := "localhost:17"
	image := fmt.Sprintf("%s/something:latest", host)
	args := []string{"packages", "-vvv", fmt.Sprintf("registry:%s", image)}

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
				assertInOutput(fmt.Sprintf("no registry credentials configured for %q, using the default keychain", host)),
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
				"SYFT_REGISTRY_AUTH_TOKEN":     "my-token",
			},
			assertions: []traitAssertion{
				assertInOutput("source=OciRegistry"),
				assertInOutput(image),
				assertInOutput(fmt.Sprintf(`using token for registry "%s"`, host)),
			},
		},
		{
			name: "not enough info fallback to keychain",
			args: args,
			env: map[string]string{
				"SYFT_REGISTRY_AUTH_AUTHORITY": host,
			},
			assertions: []traitAssertion{
				assertInOutput("source=OciRegistry"),
				assertInOutput(image),
				assertInOutput(fmt.Sprintf(`no registry credentials configured for %q, using the default keychain`, host)),
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
		{
			name: "use tls configuration",
			args: args,
			env: map[string]string{
				"SYFT_REGISTRY_AUTH_TLS_CERT": "place.crt",
				"SYFT_REGISTRY_AUTH_TLS_KEY":  "place.key",
			},
			assertions: []traitAssertion{
				assertInOutput("using custom TLS credentials from"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd, stdout, stderr := runSyft(t, test.env, test.args...)
			for _, traitAssertionFn := range test.assertions {
				traitAssertionFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}
			logOutputOnFailure(t, cmd, stdout, stderr)
		})
	}
}
