package cli

import (
	"fmt"
	"path/filepath"
	"testing"
)

const (
	// this is the number of packages that should be found in the image-pkg-coverage fixture image
	// when analyzed with the squashed scope.
	coverageImageSquashedPackageCount = 30
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
			args: []string{"scan"},
			assertions: []traitAssertion{
				assertInOutput("an image/directory argument is required"),              // specific error that should be shown
				assertInOutput("Generate a packaged-based Software Bill Of Materials"), // excerpt from help description
				assertFailingReturnCode,
			},
		},
		{
			name: "json-output-flag",
			args: []string{"scan", "-o", "json", coverageImage},
			assertions: []traitAssertion{
				assertJsonReport,
				assertInOutput(`"metadataType":"apk-db-entry"`),
				assertNotInOutput(`"metadataType":"ApkMetadata"`),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "quiet-flag-with-logger",
			args: []string{"scan", "-qvv", "-o", "json", coverageImage},
			assertions: []traitAssertion{
				assertJsonReport,
				assertNoStderr,
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "quiet-flag-with-tui",
			args: []string{"scan", "-q", "-o", "json", coverageImage},
			assertions: []traitAssertion{
				assertJsonReport,
				assertNoStderr,
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "multiple-output-flags",
			args: []string{"scan", "-o", "table", "-o", "json=" + tmp + ".tmp/multiple-output-flag-test.json", coverageImage},
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
		//	args: []string{"scan", "-vv", badBinariesImage},
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
			args: []string{"scan", coverageImage},
			assertions: []traitAssertion{
				assertJsonReport,
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "table-output-flag",
			args: []string{"scan", "-o", "table", coverageImage},
			assertions: []traitAssertion{
				assertTableReport,
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "default-output-flag",
			args: []string{"scan", coverageImage},
			assertions: []traitAssertion{
				assertTableReport,
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "legacy-json-output-flag",
			args: []string{"scan", "-o", "json", coverageImage},
			env: map[string]string{
				"SYFT_FORMAT_JSON_LEGACY": "true",
			},
			assertions: []traitAssertion{
				assertJsonReport,
				assertNotInOutput(`"metadataType":"apk-db-entry"`),
				assertInOutput(`"metadataType":"ApkMetadata"`),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "squashed-scope-flag",
			args: []string{"scan", "-o", "json", "-s", "squashed", coverageImage},
			assertions: []traitAssertion{
				assertPackageCount(coverageImageSquashedPackageCount),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "squashed-scope-flag-hidden-packages",
			args: []string{"scan", "-o", "json", "-s", "squashed", hiddenPackagesImage},
			assertions: []traitAssertion{
				assertPackageCount(14),
				// package 1: alpine-baselayout-data@3.6.5-r0 (apk)
				// package 2: alpine-baselayout@3.6.5-r0 (apk)
				// package 3: alpine-keys@2.4-r1 (apk)
				// package 4: apk-tools@2.14.4-r0 (apk)
				// package 5: busybox-binsh@1.36.1-r29 (apk)
				// package 6: busybox@1.36.1-r29 (apk)
				// package 7: ca-certificates-bundle@20240705-r0 (apk)
				// package 8: libcrypto3@3.3.1-r3 (apk)
				// package 9: libssl3@3.3.1-r3 (apk)
				// package 10: musl-utils@1.2.5-r0 (apk)
				// package 11: musl@1.2.5-r0 (apk)
				// package 12: scanelf@1.3.7-r2 (apk)
				// package 13: ssl_client@1.36.1-r29 (apk)
				// package 14: zlib@1.3.1-r1 (apk)
				assertNotInOutput(`"name":"curl"`), // hidden package
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "all-layers-scope-flag",
			args: []string{"scan", "-o", "json", "-s", "all-layers", hiddenPackagesImage},
			assertions: []traitAssertion{
				assertPackageCount(24),
				// package 1: alpine-baselayout-data@3.6.5-r0 (apk)
				// package 2: alpine-baselayout@3.6.5-r0 (apk)
				// package 3: alpine-keys@2.4-r1 (apk)
				// package 4: apk-tools@2.14.4-r0 (apk)
				// package 5: brotli-libs@1.1.0-r2 (apk)
				// package 6: busybox-binsh@1.36.1-r29 (apk)
				// package 7: busybox@1.36.1-r29 (apk)
				// package 8: c-ares@1.28.1-r0 (apk)
				// package 9: ca-certificates-bundle@20240705-r0 (apk)
				// package 10: ca-certificates@20240705-r0 (apk)
				// package 11: curl@8.9.1-r1 (apk)
				// package 12: libcrypto3@3.3.1-r3 (apk)
				// package 13: libcurl@8.9.1-r1 (apk)
				// package 14: libidn2@2.3.7-r0 (apk)
				// package 15: libpsl@0.21.5-r1 (apk)
				// package 16: libssl3@3.3.1-r3 (apk)
				// package 17: libunistring@1.2-r0 (apk)
				// package 18: musl-utils@1.2.5-r0 (apk)
				// package 19: musl@1.2.5-r0 (apk)
				// package 20: nghttp2-libs@1.62.1-r0 (apk)
				// package 21: scanelf@1.3.7-r2 (apk)
				// package 22: ssl_client@1.36.1-r29 (apk)
				// package 23: zlib@1.3.1-r1 (apk)
				// package 24: zstd-libs@1.5.6-r0 (apk)
				assertInOutput("all-layers"),
				assertInOutput(`"name":"curl"`), // hidden package
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "all-layers-scope-flag-by-env",
			args: []string{"scan", "-o", "json", hiddenPackagesImage},
			env: map[string]string{
				"SYFT_SCOPE": "all-layers",
			},
			assertions: []traitAssertion{
				assertPackageCount(24), // packages are now deduplicated for this case
				assertInOutput("all-layers"),
				assertInOutput(`"name":"curl"`), // hidden package
				assertSuccessfulReturnCode,
			},
		},
		{
			// we want to make certain that syft can catalog a single go binary and get a SBOM report that is not empty
			name: "catalog-single-go-binary",
			args: []string{"scan", "-o", "json", getSyftBinaryLocation(t)},
			assertions: []traitAssertion{
				assertJsonReport,
				assertStdoutLengthGreaterThan(1000),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "catalog-node-js-binary",
			args: []string{"scan", "-o", "json", nodeBinaryImage},
			assertions: []traitAssertion{
				assertJsonReport,
				assertInOutput("node.js"),
				assertSuccessfulReturnCode,
			},
		},
		// TODO: uncomment this test when we can use `syft config`
		//{
		//	// TODO: this could be a unit test
		//	name: "responds-to-package-cataloger-search-options",
		//	args: []string{"--help"},
		//	env: map[string]string{
		//		"SYFT_PACKAGE_SEARCH_UNINDEXED_ARCHIVES": "true",
		//		"SYFT_PACKAGE_SEARCH_INDEXED_ARCHIVES":   "false",
		//	},
		//	assertions: []traitAssertion{
		//		// the application config in the log matches that of what we expect to have been configured. Note:
		//		// we are not testing further wiring of this option, only that the config responds to
		//		// package-cataloger-level options.
		//		assertInOutput("search-unindexed-archives: true"),
		//		assertInOutput("search-indexed-archives: false"),
		//	},
		//},
		{
			name: "platform-option-wired-up",
			args: []string{"scan", "--platform", "arm64", "-o", "json", "registry:busybox:1.31"},
			assertions: []traitAssertion{
				assertInOutput("sha256:1ee006886991ad4689838d3a288e0dd3fd29b70e276622f16b67a8922831a853"), // linux/arm64 image digest
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "json-file-flag",
			args: []string{"scan", "-o", "json", "--file", filepath.Join(tmp, "output-1.json"), coverageImage},
			assertions: []traitAssertion{
				assertSuccessfulReturnCode,
				assertFileOutput(t, filepath.Join(tmp, "output-1.json"),
					assertJsonReport,
				),
			},
		},
		{
			name: "json-output-flag-to-file",
			args: []string{"scan", "-o", fmt.Sprintf("json=%s", filepath.Join(tmp, "output-2.json")), coverageImage},
			assertions: []traitAssertion{
				assertSuccessfulReturnCode,
				assertFileOutput(t, filepath.Join(tmp, "output-2.json"),
					assertJsonReport,
				),
			},
		},
		{
			name: "legacy-catalogers-option",
			// This will detect enable:
			// - python-installed-package-cataloger
			// - python-package-cataloger
			// - ruby-gemspec-cataloger
			// - ruby-installed-gemspec-cataloger
			args: []string{"packages", "-o", "json", "--catalogers", "python,gemspec", coverageImage},
			assertions: []traitAssertion{
				assertInOutput("Flag --catalogers has been deprecated, use: override-default-catalogers and select-catalogers"),
				assertPackageCount(13),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "select-catalogers-option",
			// This will detect enable:
			// - python-installed-package-cataloger
			// - ruby-installed-gemspec-cataloger
			args: []string{"scan", "-o", "json", "--select-catalogers", "python,gemspec", coverageImage},
			assertions: []traitAssertion{
				assertPackageCount(6),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "override-default-catalogers-option",
			// This will detect enable:
			// - python-installed-package-cataloger
			// - python-package-cataloger
			// - ruby-gemspec-cataloger
			// - ruby-installed-gemspec-cataloger
			args: []string{"packages", "-o", "json", "--override-default-catalogers", "python,gemspec", coverageImage},
			assertions: []traitAssertion{
				assertPackageCount(13),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "new and old cataloger options are mutually exclusive",
			args: []string{"packages", "-o", "json", "--override-default-catalogers", "python", "--catalogers", "gemspec", coverageImage},
			assertions: []traitAssertion{
				assertFailingReturnCode,
			},
		},
		{
			name: "override-default-parallelism",
			args: []string{"scan", "-vvv", "-o", "json", coverageImage},
			env: map[string]string{
				"SYFT_PARALLELISM": "2",
			},
			assertions: []traitAssertion{
				// the application config in the log matches that of what we expect to have been configured.
				assertInOutput(`parallelism: 2`),
				assertPackageCount(coverageImageSquashedPackageCount),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "default-parallelism",
			args: []string{"scan", "-vvv", "-o", "json", coverageImage},
			assertions: []traitAssertion{
				// the application config in the log matches that of what we expect to have been configured.
				assertInOutput(`parallelism: 1`),
				assertPackageCount(coverageImageSquashedPackageCount),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "password and key not in config output",
			args: []string{"scan", "-vvv", "-o", "json", coverageImage},
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
		// Testing packages alias //////////////////////////////////////////////
		{
			name: "packages-alias-command-works",
			args: []string{"packages", coverageImage},
			assertions: []traitAssertion{
				assertTableReport,
				assertInOutput("Command \"packages\" is deprecated, use `syft scan` instead"),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "packages-alias-command--output-flag",
			args: []string{"packages", "-o", "json", coverageImage},
			assertions: []traitAssertion{
				assertJsonReport,
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
	args := []string{"scan", "-vvv", image, "--from", "registry"}

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
				assertInOutput("from registry"),
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
				assertInOutput("from registry"),
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
				assertInOutput("from registry"),
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
				assertInOutput("from registry"),
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
