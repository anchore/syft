package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/anchore/syft/syft"
	"github.com/stretchr/testify/assert"
)

func TestFilterOutPackagesWithNoNameOrVersion(t *testing.T) {
	formats := syft.FormatIDs()
	commonAssertions := []traitAssertion{
		func(tb testing.TB, stdout, _ string, _ int) {
			tb.Helper()
			assert.NotContains(tb, stdout, "broken-1.0.0-py3.8.egg-info")
			assert.NotContains(tb, stdout, "broken-2.0.0")
		},
		assertSuccessfulReturnCode,
	}

	emptyFileImage := "docker-archive:" + getFixtureImage(t, "image-empty-files")
	for _, o := range formats {
		t.Run(fmt.Sprintf("format:%s", o), func(t *testing.T) {
			cmd, stdout, stderr := runSyft(t, nil, emptyFileImage, "-o", string(o))
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
