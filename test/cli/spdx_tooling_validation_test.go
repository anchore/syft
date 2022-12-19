package cli

import (
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"testing"
)

func TestSpdxValidationTooling(t *testing.T) {
	tests := []struct {
		name       string
		syftArgs   []string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			name:     "spdx validation tooling alpine",
			syftArgs: []string{"packages", "-o", "spdx", "alpine:latest"},
			env: map[string]string{
				"SYFT_FILE_METADATA_CATALOGER_ENABLED": "true",
				"SYFT_FILE_METADATA_DIGESTS":           "sha1",
			},
			assertions: []traitAssertion{
				assertSuccessfulReturnCode,
				assertInOutput("SPDXVersion: SPDX-2.3"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// generate spdx output
			cmd, stdout, stderr := runSyft(t, test.env, test.syftArgs...)
			for _, traitFn := range test.assertions {
				traitFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}

			cwd, err := os.Getwd()
			if err != nil {
				t.Fatalf("failed to get working directory: %+v", err)
			}
			f, err := os.CreateTemp(path.Join(cwd, "test-fixtures", "image-java-spdx-tools"), "test.spdx")
			if err != nil {
				log.Fatal(err)
			}
			defer os.Remove(f.Name()) // clean up

			// write file to validate
			_, err = f.Write([]byte(stdout))
			if err != nil {
				t.Fatalf("could not write to temp file: %v", err)
			}

			// validate against spdx java tooling
			fixturesPath := filepath.Join(cwd, "test-fixtures", "image-java-spdx-tools")
			cmd = exec.Command("make", "FILE="+f.Name())
			cmd.Dir = fixturesPath
			runAndShow(t, cmd)
		})
	}
}
