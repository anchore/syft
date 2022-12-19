package cli

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"
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
				assertInOutput("SPDXVersion: SPDX-2.3"),
			},
		},
		{
			name:     "spdx validation tooling json",
			syftArgs: []string{"packages", "-o", "spdx-json"},
			images:   []string{"alpine:latest"},
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
				if err != nil {
					t.Fatalf("failed to get working directory: %+v", err)
				}

				var rename string
				if strings.Contains(test.name, "json") {
					rename = "test.json"
				} else {
					rename = "test.spdx"
				}

				f, err := os.CreateTemp(path.Join(cwd, "test-fixtures", "image-java-spdx-tools"), rename)
				if err != nil {
					log.Fatal(err)
				}

				// spdx tooling only takes a file with suffix spdx
				err = os.Rename(f.Name(), filepath.Join(cwd, "test-fixtures", "image-java-spdx-tools", rename))
				if err != nil {
					log.Fatal(err)
				}

				// write file to validate
				_, err = f.Write([]byte(stdout))
				if err != nil {
					t.Fatalf("could not write to temp file: %v", err)
				}

				// validate against spdx java tooling
				fixturesPath := filepath.Join(cwd, "test-fixtures", "image-java-spdx-tools")
				fileArg := fmt.Sprintf("FILE=%s", filepath.Join(fixturesPath, rename))
				mountArg := fmt.Sprintf("BASE=%s", rename)
				cmd = exec.Command("make", "validate", fileArg, mountArg)
				cmd.Dir = fixturesPath
				runAndShow(t, cmd)
			}
		})
	}
}
