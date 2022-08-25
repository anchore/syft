package cli

import (
	"os"
	"strings"
	"testing"
)

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
		name       string
		base       string
		convert    string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			name:       "syft-format convertable to spdx-json",
			base:       "syft-json",
			convert:    "spdx-json",
			assertions: commonAssertions,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sbomArgs := []string{"dir:./test-fixtures/image-pkg-coverage", "-o", test.base}
			cmd, stdout, stderr := runSyft(t, test.env, sbomArgs...)
			if cmd.ProcessState.ExitCode() != 0 {
				t.Fatalf("failure executing syft creating an sbom")
				t.Log("STDOUT:\n", stdout)
				t.Log("STDERR:\n", stderr)
				t.Log("COMMAND:", strings.Join(cmd.Args, " "))
				return
			}

			f, err := os.CreateTemp("", "temp_sbom")
			if err != nil {
				t.Fatalf("could not create temp sbom file for convert: %s", err)
			}
			defer os.Remove(f.Name()) // clean up temp file

			if _, err := f.Write([]byte(stdout)); err != nil {
				t.Fatalf("could not write temp sbom for convert: %s", err)
			}

			convertArgs := []string{"convert", f.Name(), "-o", test.convert}
			cmd, stdout, stderr = runSyft(t, test.env, convertArgs...)
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
