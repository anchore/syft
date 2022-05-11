package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/anchore/stereoscope/pkg/imagetest"
)

func TestValidCycloneDX(t *testing.T) {
	imageFixture := func(t *testing.T) string {
		fixtureImageName := "image-pkg-coverage"
		imagetest.GetFixtureImage(t, "docker-archive", fixtureImageName)
		tarPath := imagetest.GetFixtureImageTarPath(t, fixtureImageName)
		return "docker-archive:" + tarPath
	}

	tests := []struct {
		name       string
		subcommand string
		args       []string
		fixture    func(*testing.T) string
	}{
		{
			name:       "validate cyclonedx output",
			subcommand: "packages",
			args:       []string{"-o", "cyclonedx-json"},
			fixture:    imageFixture,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixtureRef := test.fixture(t)
			args := []string{
				test.subcommand, fixtureRef, "-q",
			}
			for _, a := range test.args {
				args = append(args, a)
			}

			cmd, stdout, stderr := runSyft(t, nil, args...)
			t.Log("STDOUT:\n", stdout)
			t.Log("STDERR:\n", stderr)
			t.Log("COMMAND:", strings.Join(cmd.Args, " "))

			validateCycloneDXJSON(t, stdout)
		})
	}
}

// validate --input-format json --input-version v1_4 --input-file bom.json
func validateCycloneDXJSON(t *testing.T, stdout string) {
	f, err := os.CreateTemp("", "tmpfile-")
	if err != nil {
		t.Fatal(err)
	}

	// close and remove the temporary file at the end of the program
	defer f.Close()
	defer os.Remove(f.Name())

	data := []byte(stdout)

	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}

	args := []string{
		"validate",
		"--input-format",
		"json",
		"--input-version",
		"v1_4",
		"--input-file",
		"/sbom",
	}

	cmd, stdout, stderr := runCycloneDXInDocker(t, nil, "cyclonedx/cyclonedx-cli", f, args...)
	t.Log("STDOUT:\n", stdout)
	t.Log("STDERR:\n", stderr)
	t.Log("COMMAND:", strings.Join(cmd.Args, " "))
}
