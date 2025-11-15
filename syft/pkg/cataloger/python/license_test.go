package python

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFormatPyPiRegistryURL(t *testing.T) {
	tests := []struct {
		name          string
		version       string
		expected      string
		expectedError error
	}{
		{
			name:          "package1",
			version:       "1.0",
			expected:      "https://pypi.org/pypi/package1/1.0/json",
			expectedError: nil,
		},
		{
			name:          "package-1",
			version:       "",
			expected:      "https://pypi.org/pypi/package-1/json",
			expectedError: nil,
		},
		{
			name:          "_",
			version:       "a",
			expected:      "https://pypi.org/pypi/_/a/json",
			expectedError: nil,
		},
		{
			name:          "",
			version:       "a",
			expected:      "",
			expectedError: fmt.Errorf("unable to format pypi request for a blank package name"),
		},
	}

	cfg := DefaultCatalogerConfig()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := formatPypiRegistryURL(cfg.PypiBaseURL, test.name, test.version)

			require.Equal(t, test.expected, got)
			if test.expectedError != nil {
				require.ErrorContains(t, err, test.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}

}

func TestGetLicenseFromPypiRegistry(t *testing.T) {
	mux, url, teardown := setupPypiRegistry()
	defer teardown()

	tests := []struct {
		name            string
		version         string
		requestHandlers []handlerPath
		expected        string
		expectedError   error
	}{
		{
			name:    "certifi",
			version: "2025.10.5",
			requestHandlers: []handlerPath{
				{
					path:    "/certifi/2025.10.5/json",
					handler: generateMockPypiRegistryHandler("test-fixtures/pypi-remote/registry_response.json"),
				},
			},
			expected: "MPL-2.0",
		},
		{
			name:    "package",
			version: "1.0",
			requestHandlers: []handlerPath{
				{
					path:    "/package/1.0/json",
					handler: generateMockPypiRegistryHandlerWithStatus("", http.StatusNotFound),
				},
			},
			expected:      "",
			expectedError: fmt.Errorf("unable to get package from pypi registry"),
		},
		{
			name:    "package",
			version: "2.0",
			requestHandlers: []handlerPath{
				{
					path:    "/package/2.0/json",
					handler: generateMockPypiRegistryHandler("test-fixtures/pypi-remote/registry_response_bad.json"),
				},
			},
			expected:      "",
			expectedError: fmt.Errorf("unable to parse license from pypi registry: EOF"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// set up the mock server
			for _, handler := range tc.requestHandlers {
				mux.HandleFunc(handler.path, handler.handler)
			}
			got, err := getLicenseFromPypiRegistry(url, tc.name, tc.version)
			require.Equal(t, tc.expected, got)
			if tc.expectedError != nil {
				require.ErrorContains(t, err, tc.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

type handlerPath struct {
	path    string
	handler func(w http.ResponseWriter, r *http.Request)
}

func generateMockPypiRegistryHandler(responseFixture string) func(w http.ResponseWriter, r *http.Request) {
	return generateMockPypiRegistryHandlerWithStatus(responseFixture, http.StatusOK)
}

func generateMockPypiRegistryHandlerWithStatus(responseFixture string, mockHttpStatus int) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if mockHttpStatus != http.StatusOK {
			http.Error(w, fmt.Errorf("Error for status").Error(), http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)
		// Copy the file's content to the response writer
		file, err := os.Open(responseFixture)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = io.Copy(w, file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

// setup sets up a test HTTP server for mocking requests to a particular registry.
// The returned url is injected into the Config so the client uses the test server.
// Tests should register handlers on mux to simulate the expected request/response structure
func setupPypiRegistry() (mux *http.ServeMux, serverURL string, teardown func()) {
	// mux is the HTTP request multiplexer used with the test server.
	mux = http.NewServeMux()

	// We want to ensure that tests catch mistakes where the endpoint URL is
	// specified as absolute rather than relative. It only makes a difference
	// when there's a non-empty base URL path. So, use that. See issue #752.
	apiHandler := http.NewServeMux()
	apiHandler.Handle("/", mux)
	// server is a test HTTP server used to provide mock API responses.
	server := httptest.NewServer(apiHandler)

	return mux, server.URL, server.Close
}
