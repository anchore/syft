package cli

import "testing"

func Test_Licenses(t *testing.T) {
	testImage := getFixtureImage(t, "image-pkg-coverage")
	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			name: "licenses default with no content",
			args: []string{"scan", "-o", "json", testImage, "--from", "docker-archive"},
			env:  map[string]string{"SYFT_FORMAT_PRETTY": "true"},
			assertions: []traitAssertion{
				assertJsonReport,
				assertUnknownLicenseContent(false),
				assertSuccessfulReturnCode,
			},
		},
		// deprecated LICENSE_INCLUDE_UNKNOWN_LICENSE_CONTENT
		{
			name: "licenses with content works without deprecated LICENSE_INCLUDE_UNKNOWN_LICENSE_CONTENT",
			args: []string{"scan", "-o", "json", testImage, "--from", "docker-archive"},
			env:  map[string]string{"SYFT_FORMAT_PRETTY": "true", "SYFT_LICENSE_INCLUDE_UNKNOWN_LICENSE_CONTENT": "true"},
			assertions: []traitAssertion{
				assertJsonReport,
				assertUnknownLicenseContent(true),
				assertSuccessfulReturnCode,
			},
		},
		// use new license content configuration
		{
			name: "licenses with content works with new CONTENT configuration",
			args: []string{"scan", "-o", "json", testImage, "--from", "docker-archive"},
			env:  map[string]string{"SYFT_FORMAT_PRETTY": "true", "SYFT_LICENSE_CONTENT": "unknown"},
			assertions: []traitAssertion{
				assertJsonReport,
				assertUnknownLicenseContent(true),
				assertSuccessfulReturnCode,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd, stdout, stderr := runSyft(t, test.env, test.args...)
			for _, traitFn := range test.assertions {
				traitFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}
			logOutputOnFailure(t, cmd, stdout, stderr)
		})
	}
}
