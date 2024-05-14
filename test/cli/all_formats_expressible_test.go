package cli

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/template"
)

func TestAllFormatsExpressible(t *testing.T) {
	commonAssertions := []traitAssertion{
		func(tb testing.TB, stdout, _ string, _ int) {
			tb.Helper()
			if len(stdout) < 1000 {
				tb.Errorf("there may not be any report output (len=%d)", len(stdout))
			}
		},
		assertSuccessfulReturnCode,
	}

	encs := format.NewEncoderCollection(format.Encoders()...)
	formatIDs := encs.IDs()
	require.NotEmpty(t, formatIDs)
	for _, o := range formatIDs {
		t.Run(fmt.Sprintf("format:%s", o), func(t *testing.T) {
			args := []string{"dir:./test-fixtures/image-pkg-coverage", "-o", string(o)}
			if o == template.ID {
				args = append(args, "-t", "test-fixtures/csv.template")
			}

			cmd, stdout, stderr := runSyft(t, nil, args...)
			for _, traitFn := range commonAssertions {
				traitFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}
			logOutputOnFailure(t, cmd, stdout, stderr)
		})
	}
}

func Test_formatVersionsExpressible(t *testing.T) {
	tests := []struct {
		format    string
		assertion traitAssertion
	}{
		{
			format:    "spdx@2.1",
			assertion: assertInOutput("SPDXVersion: SPDX-2.1"),
		},
		{
			format:    "spdx@2.2",
			assertion: assertInOutput("SPDXVersion: SPDX-2.2"),
		},
		{
			format:    "spdx@2.3",
			assertion: assertInOutput("SPDXVersion: SPDX-2.3"),
		},
		{
			format:    "spdx-json@2.2",
			assertion: assertInOutput(`"spdxVersion":"SPDX-2.2"`),
		},
		{
			format:    "spdx-json@2.3",
			assertion: assertInOutput(`"spdxVersion":"SPDX-2.3"`),
		},
	}

	for _, test := range tests {
		t.Run(test.format, func(t *testing.T) {
			args := []string{"dir:./test-fixtures/image-pkg-coverage", "-o", test.format}
			cmd, stdout, stderr := runSyft(t, nil, args...)
			test.assertion(t, stdout, stderr, cmd.ProcessState.ExitCode())
			logOutputOnFailure(t, cmd, stdout, stderr)
		})
	}
}
