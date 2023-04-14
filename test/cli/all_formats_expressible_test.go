package cli

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/formats"
	"github.com/anchore/syft/syft/formats/template"
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
	formatNames := formats.AllIDs()
	require.NotEmpty(t, formatNames)
	for _, o := range formatNames {
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
