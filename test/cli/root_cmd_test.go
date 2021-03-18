package cli

import (
	"strings"
	"testing"

	"github.com/sergi/go-diff/diffmatchpatch"
)

func TestRootCmdAliasesToPackagesSubcommand(t *testing.T) {
	request := "docker-archive:" + getFixtureImage(t, "image-pkg-coverage")
	deprecationWarning := "The root command is deprecated"

	_, aliasStdout, aliasStderr := runSyftCommand(t, nil, request)

	if !strings.Contains(aliasStderr, deprecationWarning) {
		t.Errorf("missing root-packages alias deprecation warning")
	}

	_, pkgsStdout, pkgsStderr := runSyftCommand(t, nil, "packages", request)

	if strings.Contains(pkgsStderr, deprecationWarning) {
		t.Errorf("packages command should not have deprecation warning")
	}

	if aliasStdout != pkgsStdout {
		t.Errorf("packages and root command should have same report output but do not!")
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(aliasStdout, pkgsStdout, true)
		t.Error(dmp.DiffPrettyText(diffs))
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
			// note: the root command will always show the deprecation warning, so the packages command is used instead
			args: []string{"packages", "-q", request},
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
