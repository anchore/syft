package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/anchore/syft/syft"
	"github.com/stretchr/testify/assert"
)

func TestPackageMissingNameAndVersion(t *testing.T) {
	formats := syft.FormatIDs()
	commonAssertions := []traitAssertion{
		func(tb testing.TB, _, stderr string, _ int) {
			tb.Helper()
			assert.Contains(tb, stderr, "python-package-cataloger: missing package name, that is necessary for further metadata extraction")
			assert.Contains(tb, stderr, "python-package-cataloger: missing package version, that is necessary for further metadata extraction")
		},
		assertSuccessfulReturnCode,
	}

	for _, o := range formats {
		t.Run(fmt.Sprintf("format:%s", o), func(t *testing.T) {
			// TODO: does it make sense to add empty metadata for all catalogers?
			cmd, stdout, stderr := runSyft(t, nil, "dir:./test-fixtures/image-pkg-coverage/pkgs/", "-o", string(o))
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
