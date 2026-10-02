package cli

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSPDXDeterministicUUID(t *testing.T) {
	fixturePath := "dir:test-fixtures/image-pkg-coverage"

	tests := []struct {
		name           string
		env            map[string]string
		expectSameUUID bool
		runs           int
	}{
		{
			name: "deterministic UUID with deterministic-uuid flag",
			env: map[string]string{
				"SYFT_FORMAT_SPDX_JSON_DETERMINISTIC_UUID": "true",
			},
			expectSameUUID: true,
			runs:           3,
		},
		{
			name: "deterministic UUID with created-time and deterministic-uuid",
			env: map[string]string{
				"SYFT_FORMAT_SPDX_JSON_CREATED_TIME":       "1234567890",
				"SYFT_FORMAT_SPDX_JSON_DETERMINISTIC_UUID": "true",
			},
			expectSameUUID: true,
			runs:           3,
		},
		{
			name: "non-deterministic UUID without flags",
			env: map[string]string{
				"SYFT_FORMAT_SPDX_JSON_DETERMINISTIC_UUID": "false",
			},
			expectSameUUID: false,
			runs:           3,
		},
		{
			name: "created-time alone does not make UUID deterministic",
			env: map[string]string{
				"SYFT_FORMAT_SPDX_JSON_CREATED_TIME": "1234567890",
			},
			expectSameUUID: false,
			runs:           3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namespaces := make([]string, 0, tt.runs)

			for i := 0; i < tt.runs; i++ {
				args := []string{"scan", fixturePath, "-o", "spdx-json", "-q"}
				_, stdout, _ := runSyft(t, tt.env, args...)

				var doc spdxDocument
				err := json.Unmarshal([]byte(stdout), &doc)
				require.NoError(t, err, "failed to unmarshal SPDX JSON")

				namespaces = append(namespaces, doc.DocumentNamespace)

				// Also verify creation time if set
				if createdTime, ok := tt.env["SYFT_FORMAT_SPDX_JSON_CREATED_TIME"]; ok && createdTime == "1234567890" {
					assert.Equal(t, "2009-02-13T23:31:30Z", doc.CreationInfo.Created, "creation time should match the provided timestamp")
				}
			}

			// Check if all namespaces are the same or different based on expectation
			firstNamespace := namespaces[0]
			for i := 1; i < len(namespaces); i++ {
				if tt.expectSameUUID {
					assert.Equal(t, firstNamespace, namespaces[i],
						"namespaces should be identical when using deterministic UUID (run %d)", i+1)
				} else {
					assert.NotEqual(t, firstNamespace, namespaces[i],
						"namespaces should be different when not using deterministic UUID (run %d)", i+1)
				}
			}
		})
	}
}

func TestSPDXInvalidCreatedTime(t *testing.T) {
	fixturePath := "dir:test-fixtures/image-pkg-coverage"

	tests := []struct {
		name        string
		env         map[string]string
		expectError bool
	}{
		{
			name: "valid timestamp should succeed",
			env: map[string]string{
				"SYFT_FORMAT_SPDX_JSON_CREATED_TIME": "0",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"scan", fixturePath, "-o", "spdx-json", "-q"}
			cmd, stdout, _ := runSyftSafe(t, tt.env, args...)
			assert.Equal(t, 0, cmd.ProcessState.ExitCode(), "command should succeed")
			var doc spdxDocument
			err := json.Unmarshal([]byte(stdout), &doc)
			require.NoError(t, err, "failed to unmarshal SPDX JSON")
		})
	}
}

// Helper struct to parse SPDX JSON output
type spdxDocument struct {
	DocumentNamespace string       `json:"documentNamespace"`
	CreationInfo      creationInfo `json:"creationInfo"`
}

type creationInfo struct {
	Created string `json:"created"`
}
