package rekor

import (
	"net/http"
	"testing"

	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/stretchr/testify/assert"
)

func Test_getAndVerifySbomFromUuid(t *testing.T) {
	tests := []testCase{
		{
			name: "attestation hash does not match hash in rekor entry body",
			uuidsToLogEntryFile: map[string]string{
				"172326f41e80038d7c3da99a08b07d375e51995123287cfb2b4be76139176faf": "test-fixtures/log-entries/log-entry-3.json",
			},
			expectedErr: "the attestation hash could not be verified",
		},
		{
			name: "modified certificate",
			uuidsToLogEntryFile: map[string]string{
				"8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4": "test-fixtures/log-entries/log-entry-4.json",
			},
			expectedErr: "could not prove that the log entry is on rekor",
		},
		{
			name: "sbom could not be retrieved",
			uuidsToLogEntryFile: map[string]string{
				"c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4": "test-fixtures/log-entries/log-entry-1.json",
			},
			httpClient: &http.Client{
				Transport: roundTripperMock{sbomFile: "this-file-does-not-exist"},
			},
			expectedErr: "error retrieving sbom from rekor",
		},
		{
			name: "hash of sbom does not match sbom hash in attestation",
			uuidsToLogEntryFile: map[string]string{
				"c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4": "test-fixtures/log-entries/log-entry-1.json",
			},
			httpClient: &http.Client{
				Transport: roundTripperMock{sbomFile: "test-fixtures/sboms/sbom-2.txt"},
			},
			expectedErr: "could not verify retrieved sbom",
		},
		{
			name: "log entry payload is nil",
			uuidsToLogEntryFile: map[string]string{
				"c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4": returnNilPayload,
			},
			httpClient: &http.Client{
				Transport: roundTripperMock{sbomFile: "test-fixtures/sboms/sbom-1.txt"},
			},
			expectedErr: "retrieved rekor entry has no logEntryAnons",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			client := &Client{
				rekorClient: &client.Rekor{Entries: &rekorClientMock{test: test}},
				httpClient:  test.httpClient,
			}

			var uuid string
			for k := range test.uuidsToLogEntryFile {
				uuid = k
			}

			_, err := getAndVerifySbomFromUUID(uuid, client)
			assert.ErrorContains(t, err, test.expectedErr)
		})
	}
}
