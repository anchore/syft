package rekor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spdx/tools-golang/spdx"
	"github.com/stretchr/testify/assert"

	adapter "github.com/anchore/go-logger/adapter/logrus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/source"
)

type testCase struct {
	name                string
	inputFilePath       string // resolver and location are created from this
	expectedOutput      []artifact.Relationship
	uuidsToLogEntryFile map[string]string // tells the rekorClient mock what uuids and what log entries to return
	httpClient          *http.Client
	expectedErr         string
	expectedLog         string
}

func Test_CreateRekorSbomRels(t *testing.T) {
	defaultTc := &http.Client{
		Transport: roundTripperMock{sbomFile: "test-fixtures/sboms/sbom-1.txt"},
	}

	testLogger, hook := test.NewNullLogger()
	l, err := adapter.Use(testLogger, adapter.DefaultConfig())
	assert.NoError(t, err)
	log.Log = l

	tests := []testCase{
		{
			name:          "one sbom entry, one non-sbom entry",
			inputFilePath: "test-fixtures/files-to-hash/file-to-hash-1.txt",
			expectedOutput: []artifact.Relationship{
				{
					From: source.NewLocation("test-fixtures/files-to-hash/file-to-hash-1.txt").Coordinates,
					To: NewExternalRef(
						"SBOM-SPDX-ba96f4cc-d9e3-4c83-a1db-ec5456b6a9ce",
						"http://www.example.com/binary.spdx",
						spdx.SHA1,
						"eb141a8a026322e2ff6a1ec851af5268dfe59b20",
					),
					Type: artifact.DescribedByRelationship,
				},
			},
			uuidsToLogEntryFile: map[string]string{
				"8c3b99433eda340aa739dbc5759c032b120991ac239359773cad9d64a03a3e8f": "test-fixtures/log-entries/log-entry-6.json",
				"88aa67ce4f4a3fa3e8da8adb4e4799b53372f078459639e571e5583e2685c304": "test-fixtures/log-entries/log-entry-2.json",
			},
		},
		{
			name:          "rekor returns attestation with different subject sha than was asked",
			inputFilePath: "test-fixtures/files-to-hash/file-to-hash-1.txt",
			uuidsToLogEntryFile: map[string]string{
				"09f4d6138d167fc246dc69badb11b9a931395e7ca00fb38a1889d287f9d4110e": "test-fixtures/log-entries/log-entry-5.json",
			},
			httpClient: &http.Client{
				Transport: roundTripperMock{sbomFile: "test-fixtures/sboms/sbom-3.txt"},
			},
			expectedLog: "rekor returned a different entry than was asked for",
		},
		{
			name:          "sbom namespace is nil",
			inputFilePath: "test-fixtures/files-to-hash/file-to-hash-2.txt",
			uuidsToLogEntryFile: map[string]string{
				"4090e1dde58ba2a7997e1e7f66d85970fc3eba77ab65c17cd75c55c447cb43db": "test-fixtures/log-entries/log-entry-7.json",
			},
			httpClient: &http.Client{
				Transport: roundTripperMock{sbomFile: "test-fixtures/sboms/sbom-3.txt"},
			},
			expectedLog: "SPDX SBOM found on rekor for file in location test-fixtures/files-to-hash/file-to-hash-2.txt, but its namespace is empty. Ignoring SBOM.",
		},
		{
			name:          "file to hash is a folder",
			inputFilePath: "test-fixtures/",
			expectedErr:   "error reading bytes from file reader",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// set up mocks
			rekorClientMock := &rekorClientMock{test: test}
			rekorMock := &client.Rekor{
				Entries: rekorClientMock,
				Index:   rekorClientMock,
			}

			var httpClient *http.Client
			if test.httpClient == nil {
				httpClient = defaultTc
			} else {
				httpClient = test.httpClient
			}

			client := &Client{
				rekorClient: rekorMock,
				httpClient:  httpClient,
			}

			resolver := source.NewMockResolverForPaths(test.inputFilePath)
			location := source.NewLocation(test.inputFilePath)

			rels, err := CreateRekorSbomRels(resolver, location, client)

			assert.Equal(t, test.expectedOutput, rels)
			if test.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, test.expectedErr)
			}
			if test.expectedLog != "" && !logContains(hook.AllEntries(), test.expectedLog) {
				msg := fmt.Sprintf("the expected log message \"%v\" was not logged.\nThe last log message was \"%v\"", test.expectedLog, hook.LastEntry().Message)
				assert.FailNow(t, msg)
			}
		})
	}
}

/*
***************

	Functions and types to complete the interfaces in client.Rekor. Most are unimplemented.

****************
*/

const returnNilPayload = "return nil payload"

type rekorClientMock struct {
	test testCase
}

type roundTripperMock struct {
	sbomFile string
}

func (rt roundTripperMock) RoundTrip(req *http.Request) (*http.Response, error) {
	sbomBytes, err := os.ReadFile(rt.sbomFile)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewReader(sbomBytes)),
	}, nil
}

func (r *rekorClientMock) CreateLogEntry(params *entries.CreateLogEntryParams, opts ...entries.ClientOption) (*entries.CreateLogEntryCreated, error) {
	return nil, errors.New("Unimplemented")
}

func (r *rekorClientMock) GetLogEntryByIndex(params *entries.GetLogEntryByIndexParams, opts ...entries.ClientOption) (*entries.GetLogEntryByIndexOK, error) {
	return nil, errors.New("Unimplemented")
}

func (r *rekorClientMock) SearchLogQuery(params *entries.SearchLogQueryParams, opts ...entries.ClientOption) (*entries.SearchLogQueryOK, error) {
	return nil, errors.New("Unimplemented")
}

func (r *rekorClientMock) SetTransport(transport runtime.ClientTransport) {}

func (r *rekorClientMock) GetLogEntryByUUID(params *entries.GetLogEntryByUUIDParams, opts ...entries.ClientOption) (*entries.GetLogEntryByUUIDOK, error) {
	uuid := params.EntryUUID

	filePath, ok := r.test.uuidsToLogEntryFile[uuid]
	if !ok {
		return nil, errors.New("no test data file exists for uuid %v")
	}

	if filePath == returnNilPayload {
		return &entries.GetLogEntryByUUIDOK{
			Payload: nil,
		}, nil
	}

	entry := &models.LogEntry{}
	bytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading test data from file %v: \n%w", filePath, err)
	}
	if err = json.Unmarshal(bytes, entry); err != nil {
		return nil, fmt.Errorf("error unmarshaling json test data from file %v: \n%w", filePath, err)
	}

	return &entries.GetLogEntryByUUIDOK{Payload: *entry}, nil
}

// SearchIndex ignores input hash; just returns uuids in test case
func (r *rekorClientMock) SearchIndex(params *index.SearchIndexParams, opts ...index.ClientOption) (*index.SearchIndexOK, error) {
	var uuids []string
	for uuid := range r.test.uuidsToLogEntryFile {
		uuids = append(uuids, uuid)
	}

	return &index.SearchIndexOK{Payload: uuids}, nil
}

func logContains(log []*logrus.Entry, s string) bool {
	for _, entry := range log {
		if entry.Message == s {
			return true
		}
	}
	return false
}
