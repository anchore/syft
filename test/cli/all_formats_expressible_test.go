package cli

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/cmd/syft/cli/options"
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

	opts := options.DefaultOutput()
	encoders, err := opts.Encoders()
	require.NoError(t, err)

	encs := format.NewEncoderCollection(encoders...)
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
