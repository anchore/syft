package cli

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	validatorV2 = "ghcr.io/spdx/tools-java/tools-java:v1.1.8@sha256:c3b9e848083132e03b30302576b9b51adffd454f43c786f1708cc37c0861a2aa"
	validatorV3 = "ghcr.io/spdx/tools-java/tools-java:v2.0.4@sha256:15062f85b4be9688c7bf42df34ad6b84e084ed46e262e1f2dc1603795de9f7b4"
)

func TestSpdxValidationTooling(t *testing.T) {
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
		name      string
		format    string
		validator string
	}{
		{
			name:   "spdx 2.3 validation tooling tag value",
			format: "spdx",
		},
		{
			name:   "spdx 2.3 validation tooling json",
			format: "spdx-json",
		},
		{
			name:      "spdx 3.0 validation tooling json",
			format:    "spdx-json@3.0",
			validator: validatorV3,
		},
		{
			name:   "spdx 2.2 validation tooling tag value",
			format: "spdx@2.2",
		},
		{
			name:   "spdx 2.2 validation tooling json",
			format: "spdx-json@2.2",
		},
	}

	for _, image := range images {
		syftJsonFile := filepath.Join(t.TempDir(), "sbom.syft.json")

		cmd, _, stderr := runSyft(t, env, "-o", "syft-json", "--file", syftJsonFile, image)
		if cmd.ProcessState.ExitCode() != 0 {
			t.Fatalf("failed to run syft: %s", stderr)
		}

		for _, test := range tests {
			t.Run(test.name+"_"+image, func(t *testing.T) {
				t.Parallel()

				var suffix string
				if strings.Contains(test.name, "json") {
					suffix = ".json"
				} else {
					suffix = ".spdx"
				}

				dir := t.TempDir()
				sbomFile := fmt.Sprintf("sbom%s", suffix)
				sbomPath := filepath.Join(dir, sbomFile)

				cmd, _, stderr = runSyft(t, nil, "convert", syftJsonFile, "-o", test.format, "--file", sbomPath)
				if cmd.ProcessState.ExitCode() != 0 {
					t.Fatalf("failed to run syft convert: %s", stderr)
				}

				if test.validator == "" {
					test.validator = validatorV2
				}

				// validate against spdx java tooling
				validateCmd := exec.Command("docker", "run", "--rm", "-i",
					"-v", dir+":/data", test.validator, "Verify", "/data/"+sbomFile)

				stdout, stderr, err := runCommand(validateCmd, map[string]string{})
				if err != nil {
					t.Fatalf("invalid SPDX document:%v\nSTDOUT:\n%s\nSTDERR:\n%s", err, stdout, stderr)
				}
				require.Contains(t, stdout, "SPDX Document is valid")
			})
		}
	}
}
