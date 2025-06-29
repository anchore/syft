package snapsource

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSnapcraftClient_CheckSnapExists(t *testing.T) {
	tests := []struct {
		name           string
		snapName       string
		mockResponse   snapFindResponse
		statusCode     int
		expectedExists bool
		expectedSnapID string
		expectError    require.ErrorAssertionFunc
		errorContains  string
	}{
		{
			name:       "snap exists",
			snapName:   "jp-ledger",
			statusCode: http.StatusOK,
			mockResponse: snapFindResponse{
				Results: []struct {
					Name   string   `json:"name"`
					SnapID string   `json:"snap-id"`
					Snap   struct{} `json:"snap"`
				}{
					{
						Name:   "jp-ledger",
						SnapID: "jyDlMmifyQhSWGPM9fnKc1HSD7E6c47e",
						Snap:   struct{}{},
					},
				},
			},
			expectedExists: true,
			expectedSnapID: "jyDlMmifyQhSWGPM9fnKc1HSD7E6c47e",
			expectError:    require.NoError,
		},
		{
			name:       "snap does not exist",
			snapName:   "nonexistent-snap",
			statusCode: http.StatusOK,
			mockResponse: snapFindResponse{
				Results: []struct {
					Name   string   `json:"name"`
					SnapID string   `json:"snap-id"`
					Snap   struct{} `json:"snap"`
				}{},
			},
			expectedExists: false,
			expectedSnapID: "",
			expectError:    require.NoError,
		},
		{
			name:       "multiple results - exact match found",
			snapName:   "test-snap",
			statusCode: http.StatusOK,
			mockResponse: snapFindResponse{
				Results: []struct {
					Name   string   `json:"name"`
					SnapID string   `json:"snap-id"`
					Snap   struct{} `json:"snap"`
				}{
					{
						Name:   "test-snap-extra",
						SnapID: "wrong-id",
						Snap:   struct{}{},
					},
					{
						Name:   "test-snap",
						SnapID: "correct-id",
						Snap:   struct{}{},
					},
				},
			},
			expectedExists: true,
			expectedSnapID: "correct-id",
			expectError:    require.NoError,
		},
		{
			name:          "find API returns 404",
			snapName:      "test",
			statusCode:    http.StatusNotFound,
			expectError:   require.Error,
			errorContains: "find API request failed with status code 404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, defaultSeries, r.Header.Get("Snap-Device-Series"))
				assert.Equal(t, tt.snapName, r.URL.Query().Get("name-startswith"))

				w.WriteHeader(tt.statusCode)
				if tt.statusCode == http.StatusOK {
					responseBytes, err := json.Marshal(tt.mockResponse)
					require.NoError(t, err)
					w.Write(responseBytes)
				}
			}))
			defer findServer.Close()

			client := &snapcraftClient{
				FindAPIURL: findServer.URL,
				HTTPClient: &http.Client{},
			}

			exists, snapID, err := client.CheckSnapExists(tt.snapName)
			tt.expectError(t, err)
			if err != nil && tt.errorContains != "" {
				assert.Contains(t, err.Error(), tt.errorContains)
				return
			}

			assert.Equal(t, tt.expectedExists, exists)
			assert.Equal(t, tt.expectedSnapID, snapID)
		})
	}
}

func TestSnapcraftClient_GetSnapDownloadURL(t *testing.T) {
	tests := []struct {
		name           string
		snapID         snapIdentity
		infoResponse   snapcraftInfo
		infoStatusCode int
		findResponse   *snapFindResponse
		findStatusCode int
		expectedURL    string
		expectError    require.ErrorAssertionFunc
		errorContains  string
	}{
		{
			name: "successful download URL retrieval",
			snapID: snapIdentity{
				Name:         "etcd",
				Channel:      "stable",
				Architecture: "amd64",
			},
			infoStatusCode: http.StatusOK,
			infoResponse: snapcraftInfo{
				ChannelMap: []snapChannelMapEntry{
					{
						Channel: snapChannel{
							Architecture: "amd64",
							Name:         "stable",
						},
						Download: snapDownload{
							URL: "https://api.snapcraft.io/api/v1/snaps/download/etcd_123.snap",
						},
					},
				},
			},
			expectedURL: "https://api.snapcraft.io/api/v1/snaps/download/etcd_123.snap",
			expectError: require.NoError,
		},
		{
			name: "region-locked snap - exists but unavailable",
			snapID: snapIdentity{
				Name:         "jp-ledger",
				Channel:      "stable",
				Architecture: "amd64",
			},
			infoStatusCode: http.StatusNotFound,
			findStatusCode: http.StatusOK,
			findResponse: &snapFindResponse{
				Results: []struct {
					Name   string   `json:"name"`
					SnapID string   `json:"snap-id"`
					Snap   struct{} `json:"snap"`
				}{
					{
						Name:   "jp-ledger",
						SnapID: "jyDlMmifyQhSWGPM9fnKc1HSD7E6c47e",
						Snap:   struct{}{},
					},
				},
			},
			expectError:   require.Error,
			errorContains: "found snap 'jp-ledger' (id=jyDlMmifyQhSWGPM9fnKc1HSD7E6c47e) but it is unavailable for download",
		},
		{
			name: "snap truly does not exist",
			snapID: snapIdentity{
				Name:         "nonexistent",
				Channel:      "stable",
				Architecture: "amd64",
			},
			infoStatusCode: http.StatusNotFound,
			findStatusCode: http.StatusOK,
			findResponse: &snapFindResponse{
				Results: []struct {
					Name   string   `json:"name"`
					SnapID string   `json:"snap-id"`
					Snap   struct{} `json:"snap"`
				}{},
			},
			expectError:   require.Error,
			errorContains: "no snap found with name 'nonexistent'",
		},
		{
			name: "multiple architectures - find correct one",
			snapID: snapIdentity{
				Name:         "mysql",
				Channel:      "stable",
				Architecture: "arm64",
			},
			infoStatusCode: http.StatusOK,
			infoResponse: snapcraftInfo{
				ChannelMap: []snapChannelMapEntry{
					{
						Channel: snapChannel{
							Architecture: "amd64",
							Name:         "stable",
						},
						Download: snapDownload{
							URL: "https://api.snapcraft.io/api/v1/snaps/download/mysql_amd64.snap",
						},
					},
					{
						Channel: snapChannel{
							Architecture: "arm64",
							Name:         "stable",
						},
						Download: snapDownload{
							URL: "https://api.snapcraft.io/api/v1/snaps/download/mysql_arm64.snap",
						},
					},
				},
			},
			expectedURL: "https://api.snapcraft.io/api/v1/snaps/download/mysql_arm64.snap",
			expectError: require.NoError,
		},
		{
			name: "snap not found - no matching architecture",
			snapID: snapIdentity{
				Name:         "etcd",
				Channel:      "stable",
				Architecture: "s390x",
			},
			infoStatusCode: http.StatusOK,
			infoResponse: snapcraftInfo{
				ChannelMap: []snapChannelMapEntry{
					{
						Channel: snapChannel{
							Architecture: "amd64",
							Name:         "stable",
						},
						Download: snapDownload{
							URL: "https://api.snapcraft.io/api/v1/snaps/download/etcd_123.snap",
						},
					},
				},
			},
			expectError:   require.Error,
			errorContains: "no matching snap found",
		},
		{
			name: "API returns 500",
			snapID: snapIdentity{
				Name:         "etcd",
				Channel:      "stable",
				Architecture: "amd64",
			},
			infoStatusCode: http.StatusInternalServerError,
			expectError:    require.Error,
			errorContains:  "API request failed with status code 500",
		},
		{
			name: "find API fails when checking 404",
			snapID: snapIdentity{
				Name:         "test-snap",
				Channel:      "stable",
				Architecture: "amd64",
			},
			infoStatusCode: http.StatusNotFound,
			findStatusCode: http.StatusInternalServerError,
			expectError:    require.Error,
			errorContains:  "failed to check if snap exists",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectError == nil {
				tt.expectError = require.NoError
			}

			infoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, defaultSeries, r.Header.Get("Snap-Device-Series"))

				expectedPath := "/" + tt.snapID.Name
				assert.Equal(t, expectedPath, r.URL.Path)

				w.WriteHeader(tt.infoStatusCode)

				if tt.infoStatusCode == http.StatusOK {
					responseBytes, err := json.Marshal(tt.infoResponse)
					require.NoError(t, err)
					w.Write(responseBytes)
				}
			}))
			defer infoServer.Close()

			var findServer *httptest.Server
			if tt.findResponse != nil || tt.findStatusCode != 0 {
				findServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, defaultSeries, r.Header.Get("Snap-Device-Series"))
					assert.Equal(t, tt.snapID.Name, r.URL.Query().Get("name-startswith"))

					statusCode := tt.findStatusCode
					if statusCode == 0 {
						statusCode = http.StatusOK
					}
					w.WriteHeader(statusCode)

					if tt.findResponse != nil && statusCode == http.StatusOK {
						responseBytes, err := json.Marshal(tt.findResponse)
						require.NoError(t, err)
						w.Write(responseBytes)
					}
				}))
				defer findServer.Close()
			}

			client := &snapcraftClient{
				InfoAPIURL: infoServer.URL + "/",
				HTTPClient: &http.Client{},
			}
			if findServer != nil {
				client.FindAPIURL = findServer.URL
			}

			url, err := client.GetSnapDownloadURL(tt.snapID)
			tt.expectError(t, err)
			if err != nil {
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				return
			}
			assert.Equal(t, tt.expectedURL, url)
		})
	}
}

func TestSnapcraftClient_GetSnapDownloadURL_InvalidJSON(t *testing.T) {
	infoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer infoServer.Close()

	client := &snapcraftClient{
		InfoAPIURL: infoServer.URL + "/",
		HTTPClient: &http.Client{},
	}

	snapID := snapIdentity{
		Name:         "etcd",
		Channel:      "stable",
		Architecture: "amd64",
	}

	_, err := client.GetSnapDownloadURL(snapID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse JSON response")
}

func TestNewSnapcraftClient(t *testing.T) {
	client := newSnapcraftClient()

	assert.Equal(t, "https://api.snapcraft.io/v2/snaps/info/", client.InfoAPIURL)
	assert.Equal(t, "https://api.snapcraft.io/v2/snaps/find", client.FindAPIURL)
	assert.NotNil(t, client.HTTPClient)
}
