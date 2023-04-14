package cli

import (
	"fmt"
	"strings"
	"testing"
)

func TestConvertCmd(t *testing.T) {
	assertions := []traitAssertion{
		assertInOutput("PackageName: musl-utils"),
		assertSuccessfulReturnCode,
	}

	tests := []struct {
		from string
		to   string
	}{
		{from: "syft-json", to: "spdx-tag-value"},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("from %s to %s", test.from, test.to), func(t *testing.T) {
			sbomArgs := []string{"dir:./test-fixtures/image-pkg-coverage", "-o", test.from}
			cmd, stdout, stderr := runSyft(t, nil, sbomArgs...)
			if cmd.ProcessState.ExitCode() != 0 {
				t.Log("STDOUT:\n", stdout)
				t.Log("STDERR:\n", stderr)
				t.Log("COMMAND:", strings.Join(cmd.Args, " "))
				t.Fatalf("failure executing syft creating an sbom")
				return
			}

			convertArgs := []string{"convert", "-", "-o", test.to}
			cmd = getSyftCommand(t, convertArgs...)

			cmd.Stdin = strings.NewReader(stdout)
			stdout, stderr = runCommandObj(t, cmd, nil, false)

			for _, traitFn := range assertions {
				traitFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}
			logOutputOnFailure(t, cmd, stdout, stderr)
		})
	}
}
