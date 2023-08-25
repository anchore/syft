package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/anchore/stereoscope/pkg/imagetest"
)

// We have schema validation mechanims in schema/cyclonedx/
// This test allows us to double check that validation against the cyclonedx-cli tool
func TestValidCycloneDX(t *testing.T) {
	imageFixture := func(t *testing.T) string {
		fixtureImageName := "image-pkg-coverage"
		imagetest.GetFixtureImage(t, "docker-archive", fixtureImageName)
		tarPath := imagetest.GetFixtureImageTarPath(t, fixtureImageName)
		return "docker-archive:" + tarPath
	}

	// TODO update image to exercise entire cyclonedx schema
	tests := []struct {
		name       string
		subcommand string
		args       []string
		fixture    func(*testing.T) string
		assertions []traitAssertion
	}{
		{
			name:       "validate cyclonedx output",
			subcommand: "packages",
			args:       []string{"-o", "cyclonedx-json"},
			fixture:    imageFixture,
			assertions: []traitAssertion{
				assertSuccessfulReturnCode,
				assertValidCycloneDX,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixtureRef := test.fixture(t)
			args := []string{
				test.subcommand, fixtureRef, "-q",
			}
			args = append(args, test.args...)

			cmd, stdout, stderr := runSyft(t, nil, args...)
			for _, traitFn := range test.assertions {
				traitFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}
			logOutputOnFailure(t, cmd, stdout, stderr)

			validateCycloneDXJSON(t, stdout)
		})
	}
}

func assertValidCycloneDX(tb testing.TB, stdout, stderr string, rc int) {
	tb.Helper()
	f, err := os.CreateTemp("", "tmpfile-")
	if err != nil {
		tb.Fatal(err)
	}

	// close and remove the temporary file at the end of the program
	defer f.Close()
	defer os.Remove(f.Name())

	data := []byte(stdout)

	if _, err := f.Write(data); err != nil {
		tb.Fatal(err)
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

	cmd, stdout, stderr := runCycloneDXInDocker(tb, nil, "cyclonedx/cyclonedx-cli", f, args...)
	if cmd.ProcessState.ExitCode() != 0 {
		tb.Errorf("expected no validation failures for cyclonedx-cli but got rc=%d", rc)
	}

	logOutputOnFailure(tb, cmd, stdout, stderr)
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
	if strings.Contains(stdout, "BOM is not valid") {
		t.Errorf("expected no validation failures for cyclonedx-cli but found invalid BOM")
	}

	logOutputOnFailure(t, cmd, stdout, stderr)
}
