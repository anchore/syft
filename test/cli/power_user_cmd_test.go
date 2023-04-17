package cli

import (
	"testing"
)

func TestPowerUserCmdFlags(t *testing.T) {
	secretsFixture := getFixtureImage(t, "image-secrets")
	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			name: "no-args-shows-help",
			args: []string{"power-user"},
			assertions: []traitAssertion{
				assertInOutput("an image/directory argument is required"), // specific error that should be shown
				assertInOutput("Run bulk operations on container images"), // excerpt from help description
				assertFailingReturnCode,
			},
		},
		{
			name: "default-results-w-pkg-coverage",
			args: []string{"power-user", "docker-archive:" + getFixtureImage(t, "image-pkg-coverage")},
			assertions: []traitAssertion{
				assertNotInOutput(" command is deprecated"),     // only the root command should be deprecated
				assertInOutput(`"type": "RegularFile"`),         // proof of file-metadata data
				assertInOutput(`"algorithm": "sha256"`),         // proof of file-metadata default digest algorithm of sha256
				assertInOutput(`"metadataType": "ApkMetadata"`), // proof of package artifacts data
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "content-cataloger-wired-up",
			args: []string{"power-user", "docker-archive:" + secretsFixture},
			env: map[string]string{
				"SYFT_FILE_CONTENTS_GLOBS": "/api-key.txt",
			},
			assertions: []traitAssertion{
				assertInOutput(`"contents": "c29tZV9BcEkta0V5ID0gIjEyMzQ1QTdhOTAxYjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MCIK"`), // proof of the content cataloger
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "default-dir-results-w-pkg-coverage",
			args: []string{"power-user", "dir:test-fixtures/image-pkg-coverage"},
			assertions: []traitAssertion{
				assertNotInOutput(" command is deprecated"),     // only the root command should be deprecated
				assertInOutput(`"type": "RegularFile"`),         // proof of file-metadata data
				assertInOutput(`"algorithm": "sha256"`),         // proof of file-metadata default digest algorithm of sha256
				assertInOutput(`"metadataType": "ApkMetadata"`), // proof of package artifacts data
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "default-secrets-results-w-reveal-values",
			env: map[string]string{
				"SYFT_SECRETS_REVEAL_VALUES": "true",
			},
			args: []string{"power-user", "docker-archive:" + secretsFixture},
			assertions: []traitAssertion{
				assertInOutput(`"classification": "generic-api-key"`),                            // proof of the secrets cataloger finding something
				assertInOutput(`"12345A7a901b345678901234567890123456789012345678901234567890"`), // proof of the secrets cataloger finding the api key
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "default-secret-results-dont-reveal-values",
			args: []string{"power-user", "docker-archive:" + secretsFixture},
			assertions: []traitAssertion{
				assertInOutput(`"classification": "generic-api-key"`),                               // proof of the secrets cataloger finding something
				assertNotInOutput(`"12345A7a901b345678901234567890123456789012345678901234567890"`), // proof of the secrets cataloger finding the api key
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "default-secrets-dir-results-w-reveal-values",
			env: map[string]string{
				"SYFT_SECRETS_REVEAL_VALUES": "true",
			},
			args: []string{"power-user", "dir:test-fixtures/image-secrets-dir"},
			assertions: []traitAssertion{
				assertInOutput(`"classification": "generic-api-key"`),                            // proof of the secrets cataloger finding something
				assertInOutput(`"12345A7a901b345678901234567890123456789012345678901234567890"`), // proof of the secrets cataloger finding the api key
				assertSuccessfulReturnCode,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd, stdout, stderr := runSyftSafe(t, test.env, test.args...)
			for _, traitFn := range test.assertions {
				traitFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}
			logOutputOnFailure(t, cmd, stdout, stderr)
		})
	}
}
