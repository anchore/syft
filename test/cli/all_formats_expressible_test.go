package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft"
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
	formats := syft.FormatIDs()
	require.NotEmpty(t, formats)
	for _, o := range formats {
		t.Run(fmt.Sprintf("format:%s", o), func(t *testing.T) {
			args := []string{"dir:./test-fixtures/image-pkg-coverage", "-o", string(o)}
			if o == template.ID {
				args = append(args, "-t", "test-fixtures/csv.template")
			}

			cmd, stdout, stderr := runSyft(t, nil, args...)
			for _, traitFn := range commonAssertions {
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
