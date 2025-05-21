package snapsource

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSnapRequest(t *testing.T) {
	tests := []struct {
		name            string
		request         string
		expectedName    string
		expectedChannel string
	}{
		{
			name:            "snap name only - uses default channel",
			request:         "etcd",
			expectedName:    "etcd",
			expectedChannel: "stable",
		},
		{
			name:            "snap with beta channel",
			request:         "etcd@beta",
			expectedName:    "etcd",
			expectedChannel: "beta",
		},
		{
			name:            "snap with edge channel",
			request:         "etcd@edge",
			expectedName:    "etcd",
			expectedChannel: "edge",
		},
		{
			name:            "snap with version track",
			request:         "etcd@2.3/stable",
			expectedName:    "etcd",
			expectedChannel: "2.3/stable",
		},
		{
			name:            "snap with complex channel path",
			request:         "mysql@8.0/candidate",
			expectedName:    "mysql",
			expectedChannel: "8.0/candidate",
		},
		{
			name:            "snap with multiple @ symbols - only first is delimiter",
			request:         "app@beta@test",
			expectedName:    "app",
			expectedChannel: "beta@test",
		},
		{
			name:            "empty snap name with channel",
			request:         "@stable",
			expectedName:    "",
			expectedChannel: "stable",
		},
		{
			name:            "snap name with empty channel - uses default",
			request:         "etcd@",
			expectedName:    "etcd",
			expectedChannel: "stable",
		},
		{
			name:            "hyphenated snap name",
			request:         "hello-world@stable",
			expectedName:    "hello-world",
			expectedChannel: "stable",
		},
		{
			name:            "snap name with numbers",
			request:         "app123",
			expectedName:    "app123",
			expectedChannel: "stable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, channel := parseSnapRequest(tt.request)
			assert.Equal(t, tt.expectedName, name)
			assert.Equal(t, tt.expectedChannel, channel)
		})
	}
}

func TestGetSnapDownloadURL(t *testing.T) {
	tests := []struct {
		name          string
		snapID        snapIdentity
		mockResponse  snapcraftInfo
		statusCode    int
		expectedURL   string
		expectError   require.ErrorAssertionFunc
		errorContains string
	}{
		{
			name: "successful download URL retrieval",
			snapID: snapIdentity{
				Name:         "etcd",
				Channel:      "stable",
				Architecture: "amd64",
			},
			statusCode: http.StatusOK,
			mockResponse: snapcraftInfo{
				ChannelMap: []struct {
					Channel struct {
						Architecture string `json:"architecture"`
						Name         string `json:"name"`
					} `json:"channel"`
					Download struct {
						URL string `json:"url"`
					} `json:"download"`
				}{
					{
						Channel: struct {
							Architecture string `json:"architecture"`
							Name         string `json:"name"`
						}{
							Architecture: "amd64",
							Name:         "stable",
						},
						Download: struct {
							URL string `json:"url"`
						}{
							URL: "https://api.snapcraft.io/api/v1/snaps/download/etcd_123.snap",
						},
					},
				},
			},
			expectedURL: "https://api.snapcraft.io/api/v1/snaps/download/etcd_123.snap",
		},
		{
			name: "multiple architectures - find correct one",
			snapID: snapIdentity{
				Name:         "mysql",
				Channel:      "stable",
				Architecture: "arm64",
			},
			statusCode: http.StatusOK,
			mockResponse: snapcraftInfo{
				ChannelMap: []struct {
					Channel struct {
						Architecture string `json:"architecture"`
						Name         string `json:"name"`
					} `json:"channel"`
					Download struct {
						URL string `json:"url"`
					} `json:"download"`
				}{
					{
						Channel: struct {
							Architecture string `json:"architecture"`
							Name         string `json:"name"`
						}{
							Architecture: "amd64",
							Name:         "stable",
						},
						Download: struct {
							URL string `json:"url"`
						}{
							URL: "https://api.snapcraft.io/api/v1/snaps/download/mysql_amd64.snap",
						},
					},
					{
						Channel: struct {
							Architecture string `json:"architecture"`
							Name         string `json:"name"`
						}{
							Architecture: "arm64",
							Name:         "stable",
						},
						Download: struct {
							URL string `json:"url"`
						}{
							URL: "https://api.snapcraft.io/api/v1/snaps/download/mysql_arm64.snap",
						},
					},
				},
			},
			expectedURL: "https://api.snapcraft.io/api/v1/snaps/download/mysql_arm64.snap",
		},
		{
			name: "multiple channels - find correct one",
			snapID: snapIdentity{
				Name:         "etcd",
				Channel:      "beta",
				Architecture: "amd64",
			},
			statusCode: http.StatusOK,
			mockResponse: snapcraftInfo{
				ChannelMap: []struct {
					Channel struct {
						Architecture string `json:"architecture"`
						Name         string `json:"name"`
					} `json:"channel"`
					Download struct {
						URL string `json:"url"`
					} `json:"download"`
				}{
					{
						Channel: struct {
							Architecture string `json:"architecture"`
							Name         string `json:"name"`
						}{
							Architecture: "amd64",
							Name:         "stable",
						},
						Download: struct {
							URL string `json:"url"`
						}{
							URL: "https://api.snapcraft.io/api/v1/snaps/download/etcd_stable.snap",
						},
					},
					{
						Channel: struct {
							Architecture string `json:"architecture"`
							Name         string `json:"name"`
						}{
							Architecture: "amd64",
							Name:         "beta",
						},
						Download: struct {
							URL string `json:"url"`
						}{
							URL: "https://api.snapcraft.io/api/v1/snaps/download/etcd_beta.snap",
						},
					},
				},
			},
			expectedURL: "https://api.snapcraft.io/api/v1/snaps/download/etcd_beta.snap",
		},
		{
			name: "snap not found - no matching architecture",
			snapID: snapIdentity{
				Name:         "etcd",
				Channel:      "stable",
				Architecture: "s390x",
			},
			statusCode: http.StatusOK,
			mockResponse: snapcraftInfo{
				ChannelMap: []struct {
					Channel struct {
						Architecture string `json:"architecture"`
						Name         string `json:"name"`
					} `json:"channel"`
					Download struct {
						URL string `json:"url"`
					} `json:"download"`
				}{
					{
						Channel: struct {
							Architecture string `json:"architecture"`
							Name         string `json:"name"`
						}{
							Architecture: "amd64",
							Name:         "stable",
						},
						Download: struct {
							URL string `json:"url"`
						}{
							URL: "https://api.snapcraft.io/api/v1/snaps/download/etcd_123.snap",
						},
					},
				},
			},
			expectError:   require.Error,
			errorContains: "no matching snap found",
		},
		{
			name: "snap not found - no matching channel",
			snapID: snapIdentity{
				Name:         "etcd",
				Channel:      "candidate",
				Architecture: "amd64",
			},
			statusCode: http.StatusOK,
			mockResponse: snapcraftInfo{
				ChannelMap: []struct {
					Channel struct {
						Architecture string `json:"architecture"`
						Name         string `json:"name"`
					} `json:"channel"`
					Download struct {
						URL string `json:"url"`
					} `json:"download"`
				}{
					{
						Channel: struct {
							Architecture string `json:"architecture"`
							Name         string `json:"name"`
						}{
							Architecture: "amd64",
							Name:         "stable",
						},
						Download: struct {
							URL string `json:"url"`
						}{
							URL: "https://api.snapcraft.io/api/v1/snaps/download/etcd_123.snap",
						},
					},
				},
			},
			expectError:   require.Error,
			errorContains: "no matching snap found",
		},
		{
			name: "API returns 404",
			snapID: snapIdentity{
				Name:         "nonexistent",
				Channel:      "stable",
				Architecture: "amd64",
			},
			statusCode:    http.StatusNotFound,
			expectError:   require.Error,
			errorContains: "API request failed with status code 404",
		},
		{
			name: "API returns 500",
			snapID: snapIdentity{
				Name:         "etcd",
				Channel:      "stable",
				Architecture: "amd64",
			},
			statusCode:    http.StatusInternalServerError,
			expectError:   require.Error,
			errorContains: "API request failed with status code 500",
		},
		{
			name: "empty channel map",
			snapID: snapIdentity{
				Name:         "etcd",
				Channel:      "stable",
				Architecture: "amd64",
			},
			statusCode: http.StatusOK,
			mockResponse: snapcraftInfo{
				ChannelMap: []struct {
					Channel struct {
						Architecture string `json:"architecture"`
						Name         string `json:"name"`
					} `json:"channel"`
					Download struct {
						URL string `json:"url"`
					} `json:"download"`
				}{}, // empty channel map
			},
			expectError:   require.Error,
			errorContains: "no matching snap found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectError == nil {
				tt.expectError = require.NoError
			}
			// create mock server...
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, defaultSeries, r.Header.Get("Snap-Device-Series"))

				expectedPath := "/" + tt.snapID.Name
				assert.Equal(t, expectedPath, r.URL.Path)

				w.WriteHeader(tt.statusCode)

				if tt.statusCode == http.StatusOK {
					responseBytes, err := json.Marshal(tt.mockResponse)
					require.NoError(t, err)
					w.Write(responseBytes)
				}
			}))
			defer server.Close()

			url, err := getSnapDownloadURL(server.URL+"/", tt.snapID)
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

func TestGetSnapDownloadURL_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	snapID := snapIdentity{
		Name:         "etcd",
		Channel:      "stable",
		Architecture: "amd64",
	}

	_, err := getSnapDownloadURL(server.URL+"/", snapID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse JSON response")
}
