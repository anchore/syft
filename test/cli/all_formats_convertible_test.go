package cli

import (
	"os"
	"strings"
	"testing"
)

type conversion struct {
	To   string
	From string
}

func TestConvertCmdFlags(t *testing.T) {
	commonAssertions := []traitAssertion{
		func(tb testing.TB, stdout, _ string, _ int) {
			tb.Helper()
			if len(stdout) < 1000 {
				tb.Errorf("there may not be any report output (len=%d)", len(stdout))
			}
		},
		assertSuccessfulReturnCode,
	}

	tests := []struct {
		name        string
		conversions []conversion
		env         map[string]string
		assertions  []traitAssertion
	}{
		{
			name: "syft-format convertable to spdx-json",
			conversions: []conversion{
				{To: "syft-json", From: "spdx-json"},
				{To: "syft-json", From: "cyclonedx-json"},
				{To: "spdx-json", From: "syft-json"},
				{To: "spdx-json", From: "cyclonedx-json"},
				{To: "cyclonedx-json", From: "syft-json"},
				{To: "cyclonedx-json", From: "spdx-json"},
			},
			assertions: commonAssertions,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, c := range test.conversions {
				sbomArgs := []string{"dir:./test-fixtures/image-pkg-coverage", "-o", c.From}
				cmd, stdout, stderr := runSyft(t, test.env, sbomArgs...)
				if cmd.ProcessState.ExitCode() != 0 {
					t.Fatalf("failure executing syft creating an sbom")
					t.Log("STDOUT:\n", stdout)
					t.Log("STDERR:\n", stderr)
					t.Log("COMMAND:", strings.Join(cmd.Args, " "))
					return
				}

				tempDir := t.TempDir()
				sbomFile := filepath.Join(tempDir, "sbom.json")
				require.NoError(t, os.WriteFile(sbomFile, stdout, 0666))

				convertArgs := []string{"convert", f.Name(), "-o", c.To}
				cmd, stdout, stderr = runSyft(t, test.env, convertArgs...)
				for _, traitFn := range test.assertions {
					traitFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
				}
				if t.Failed() {
					t.Log("STDOUT:\n", stdout)
					t.Log("STDERR:\n", stderr)
					t.Log("COMMAND:", strings.Join(cmd.Args, " "))
				}
			}
		})
	}
}
