package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/imagetest"
)

func TestSpdxValidationTooling(t *testing.T) {
	// note: the external tooling requires that the daemon explicitly has the image loaded, not just that
	// we can get the image from a cache tar.
	imgTag := imagetest.LoadFixtureImageIntoDocker(t, "image-java-spdx-tools")

	images := []string{
		"alpine:3.17.3@sha256:b6ca290b6b4cdcca5b3db3ffa338ee0285c11744b4a6abaa9627746ee3291d8d",
		"photon:3.0@sha256:888675e193418d924feea262cf639c46532b63c2027a39fd3ac75383b3c1130e",
		"debian:stable@sha256:729c2433e196207749a86f1d86e0106822041bb280b4200cf7a4db97608f6d3a",
	}

	env := map[string]string{
		"SYFT_FILE_METADATA_CATALOGER_ENABLED": "true",
		"SYFT_FILE_CONTENTS_CATALOGER_ENABLED": "true",
		"SYFT_FILE_METADATA_DIGESTS":           "sha1",
	}

	tests := []struct {
		name     string
		syftArgs []string
		images   []string
		setup    func(t *testing.T)
		env      map[string]string
	}{
		{
			name:     "spdx validation tooling tag value",
			syftArgs: []string{"scan", "-o", "spdx"},
			images:   images,
			env:      env,
		},
		{
			name:     "spdx validation tooling json",
			syftArgs: []string{"scan", "-o", "spdx-json"},
			images:   images,
			env:      env,
		},
	}

	for _, test := range tests {
		for _, image := range test.images {
			t.Run(test.name+"_"+image, func(t *testing.T) {

				args := append(test.syftArgs, image)

				var suffix string
				if strings.Contains(test.name, "json") {
					suffix = ".json"
				} else {
					suffix = ".spdx"
				}

				dir := t.TempDir()
				sbomPath := filepath.Join(dir, fmt.Sprintf("sbom%s", suffix))

				args = append(args, "--file", sbomPath)

				cmd, _, stderr := runSyft(t, test.env, args...)
				if cmd.ProcessState.ExitCode() != 0 {
					t.Fatalf("failed to run syft: %s", stderr)
				}

				cwd, err := os.Getwd()
				require.NoError(t, err)

				// validate against spdx java tooling
				fileArg := fmt.Sprintf("DIR=%s", dir)
				mountArg := fmt.Sprintf("BASE=%s", path.Base(sbomPath))
				imageArg := fmt.Sprintf("IMAGE=%s", imgTag)

				validateCmd := exec.Command("make", "validate", fileArg, mountArg, imageArg)
				validateCmd.Dir = filepath.Join(cwd, "test-fixtures", "image-java-spdx-tools")

				stdout, stderr, err := runCommand(validateCmd, map[string]string{})
				if err != nil {
					t.Fatalf("invalid SPDX document:%v\nSTDOUT:\n%s\nSTDERR:\n%s", err, stdout, stderr)
				}
			})
		}
	}
}
