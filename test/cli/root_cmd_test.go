package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/stretchr/testify/assert"
)

func TestRootCmdAliasesToPackagesSubcommand(t *testing.T) {
	request := "docker-archive:" + getFixtureImage(t, "image-pkg-coverage")

	tests := []struct {
		name       string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			name: "go-case",
			assertions: []traitAssertion{
				assertTableReport,
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "respond-to-output-binding",
			env: map[string]string{
				"SYFT_OUTPUT": "text",
			},
			assertions: []traitAssertion{
				assertInOutput("[Image]"),
				assertSuccessfulReturnCode,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			aliasCmd, aliasStdout, aliasStderr := runSyft(t, test.env, request)
			for _, traitFn := range test.assertions {
				traitFn(t, aliasStdout, aliasStderr, aliasCmd.ProcessState.ExitCode())
			}

			pkgCmd, pkgsStdout, pkgsStderr := runSyft(t, test.env, "packages", request)
			for _, traitFn := range test.assertions {
				traitFn(t, pkgsStdout, pkgsStderr, pkgCmd.ProcessState.ExitCode())
			}

			if aliasStdout != pkgsStdout {
				t.Errorf("packages and root command should have same report output but do not!")
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(aliasStdout, pkgsStdout, true)
				t.Error(dmp.DiffPrettyText(diffs))
			}
		})
	}
}

func TestPersistentFlags(t *testing.T) {
	request := "docker-archive:" + getFixtureImage(t, "image-pkg-coverage")

	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			name: "quiet-flag",
			// note: the root command will always show the deprecation warning, so the scan command is used instead
			args: []string{"scan", "-q", request},
			assertions: []traitAssertion{
				func(tb testing.TB, stdout, stderr string, rc int) {
					// ensure there is no status
					if len(stderr) != 0 {
						tb.Errorf("should have seen no stderr output, got %d bytes", len(stderr))
					}
					// ensure there is still a report
					if len(stdout) == 0 {
						tb.Errorf("should have seen a report on stdout, got nothing")
					}
				},
			},
		},
		{
			name: "info-log-flag",
			args: []string{"-v", request},
			assertions: []traitAssertion{
				assertLoggingLevel("info"),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "debug-log-flag",
			args: []string{"-vv", request},
			assertions: []traitAssertion{
				assertLoggingLevel("debug"),
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

func TestLogFile(t *testing.T) {
	request := "docker-archive:" + getFixtureImage(t, "image-pkg-coverage")

	envLogFile := filepath.Join(os.TempDir(), "a-pretty-log-file.log")
	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		assertions []traitAssertion
		cleanup    func()
	}{
		{
			name: "env-var-log-file-name",
			args: []string{"-vv", request},
			env:  map[string]string{"SYFT_LOG_FILE": envLogFile},
			assertions: []traitAssertion{
				func(tb testing.TB, stdout, stderr string, rc int) {
					tb.Helper()
					_, err := os.Stat(envLogFile)
					assert.NoError(t, err)
				},
			},
			cleanup: func() { assert.NoError(t, os.Remove(envLogFile)) },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Cleanup(test.cleanup)

			cmd, stdout, stderr := runSyft(t, test.env, test.args...)
			for _, traitFn := range test.assertions {
				traitFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}
			logOutputOnFailure(t, cmd, stdout, stderr)
		})
	}
}
