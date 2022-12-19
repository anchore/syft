package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSpdxValidationTooling(t *testing.T) {
	tests := []struct {
		name       string
		syftArgs   []string
		images     []string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			name:     "spdx validation tooling tag value",
			syftArgs: []string{"packages", "-o", "spdx"},
			images:   []string{"alpine:latest", "photon:3.0", "debian:latest"},
			env: map[string]string{
				"SYFT_FILE_METADATA_CATALOGER_ENABLED": "true",
				"SYFT_FILE_METADATA_DIGESTS":           "sha1",
			},
			assertions: []traitAssertion{
				assertSuccessfulReturnCode,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, image := range test.images {
				args := append(test.syftArgs, image)
				cmd, stdout, stderr := runSyft(t, test.env, args...)
				for _, traitFn := range test.assertions {
					traitFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
				}

				cwd, err := os.Getwd()
				require.NoError(t, err)

				f, err := os.CreateTemp(t.TempDir(), "temp")
				require.NoError(t, err)

				// spdx tooling only takes a file with suffix spdx
				rename := path.Join(path.Dir(f.Name()), fmt.Sprintf("%s.spdx", path.Base(f.Name())))
				err = os.Rename(f.Name(), rename)
				require.NoError(t, err)

				// write file for validation
				_, err = f.Write([]byte(stdout))
				require.NoError(t, err)

				// validate against spdx java tooling
				fixturesPath := filepath.Join(cwd, "test-fixtures", "image-java-spdx-tools")
				fileArg := fmt.Sprintf("FILE=%s", rename)
				mountArg := fmt.Sprintf("BASE=%s", path.Base(rename))
				makeCmd := exec.Command("make", "validate", fileArg, mountArg)
				makeCmd.Dir = fixturesPath

				err = makeCmd.Run()
				require.NoError(t, err)
				assertSuccessfulReturnCode(t, "", "", makeCmd.ProcessState.ExitCode())
			}
		})
	}
}
