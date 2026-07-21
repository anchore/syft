package cli

import (
	"testing"
)

func TestCatalogerCapsExperimentalFeatureGate(t *testing.T) {
	// the "caps" subcommand description from cataloger_caps.go
	const capsSubcommandText = "Show detailed capabilities of catalogers"

	// table header from the cataloger info output
	const capsTableHeader = "ECOSYSTEM"

	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		assertions []traitAssertion
	}{
		// tests without SYFT_EXP_CAPABILITIES set
		{
			name: "cataloger help does not show caps subcommand without env var",
			args: []string{"cataloger", "--help"},
			assertions: []traitAssertion{
				assertNotInOutput(capsSubcommandText),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "cataloger caps command shows help without env var",
			args: []string{"cataloger", "info"},
			assertions: []traitAssertion{
				// when the subcommand is not registered, the parent help is shown
				assertNotInOutput(capsTableHeader),
				assertInOutput("Available Commands"),
				assertSuccessfulReturnCode,
			},
		},
		// tests with SYFT_EXP_CAPABILITIES=false
		{
			name: "cataloger help does not show caps subcommand with env var false",
			args: []string{"cataloger", "--help"},
			env: map[string]string{
				"SYFT_EXP_CAPABILITIES": "false",
			},
			assertions: []traitAssertion{
				assertNotInOutput(capsSubcommandText),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "cataloger caps command shows help with env var false",
			args: []string{"cataloger", "info"},
			env: map[string]string{
				"SYFT_EXP_CAPABILITIES": "false",
			},
			assertions: []traitAssertion{
				// when the subcommand is not registered, the parent help is shown
				assertNotInOutput(capsTableHeader),
				assertInOutput("Available Commands"),
				assertSuccessfulReturnCode,
			},
		},
		// tests with SYFT_EXP_CAPABILITIES=true
		{
			name: "cataloger help shows caps subcommand with env var true",
			args: []string{"cataloger", "--help"},
			env: map[string]string{
				"SYFT_EXP_CAPABILITIES": "true",
			},
			assertions: []traitAssertion{
				assertInOutput(capsSubcommandText),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "cataloger caps command shows capabilities table with env var true",
			args: []string{"cataloger", "info"},
			env: map[string]string{
				"SYFT_EXP_CAPABILITIES": "true",
			},
			assertions: []traitAssertion{
				// the info command shows the capabilities table
				assertInOutput(capsTableHeader),
				assertSuccessfulReturnCode,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd, stdout, stderr := runSyftSafe(t, test.env, test.args...)
			for _, traitFn := range test.assertions {
				traitFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}
			logOutputOnFailure(t, cmd, stdout, stderr)
		})
	}
}
