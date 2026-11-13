package file

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/clio"
)

func TestGetter_GetFile(t *testing.T) {
	testCases := []struct {
		name          string
		prepareClient func(*http.Client)
		assert        assert.ErrorAssertionFunc
	}{
		{
			name:   "client trusts server's CA",
			assert: assert.NoError,
		},
		{
			name:          "client doesn't trust server's CA",
			prepareClient: removeTrustedCAs,
			assert:        assertUnknownAuthorityError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			requestPath := "/foo"

			server := newTestServer(t, withResponseForPath(t, requestPath, testFileContent))
			t.Cleanup(server.Close)

			httpClient := getClient(t, server)
			if tc.prepareClient != nil {
				tc.prepareClient(httpClient)
			}

			getter := NewGetter(testID, httpClient)
			requestURL := createRequestURL(t, server, requestPath)

			tempDir := t.TempDir()
			tempFile := path.Join(tempDir, "some-destination-file")

			err := getter.GetFile(tempFile, requestURL)
			tc.assert(t, err)
		})
	}
}

func TestGetter_GetFile_WritesContentWithUserAgent(t *testing.T) {
	requestPath := "/foo"
	var gotUserAgent string

	server := newTestServer(t, func(mux *http.ServeMux) {
		mux.HandleFunc(requestPath, func(w http.ResponseWriter, req *http.Request) {
			gotUserAgent = req.UserAgent()
			_, _ = w.Write(testFileContent)
		})
	})
	t.Cleanup(server.Close)

	monitor := progress.NewManual(-1)
	dst := path.Join(t.TempDir(), "nested", "some-destination-file")

	err := NewGetter(testID, getClient(t, server)).GetFile(dst, createRequestURL(t, server, requestPath), monitor)
	require.NoError(t, err)

	got, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, testFileContent, got)
	assert.Equal(t, "test-app v0.5.3", gotUserAgent)
	assert.Equal(t, int64(len(testFileContent)), monitor.Current())
}

func TestGetter_GetFile_Errors(t *testing.T) {
	server := newTestServer(t, withResponseForPath(t, "/foo", testFileContent))
	t.Cleanup(server.Close)

	testCases := []struct {
		name    string
		src     string
		wantErr string
	}{
		{
			name:    "non-200 response",
			src:     createRequestURL(t, server, "/missing"),
			wantErr: "404 Not Found",
		},
		{
			name:    "unsupported scheme",
			src:     "s3://bucket/something.snap",
			wantErr: `unsupported URL scheme "s3"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := NewGetter(testID, getClient(t, server)).GetFile(path.Join(t.TempDir(), "dst"), tc.src)
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func assertUnknownAuthorityError(t assert.TestingT, err error, _ ...any) bool {
	return assert.ErrorAs(t, err, &x509.UnknownAuthorityError{})
}

func removeTrustedCAs(client *http.Client) {
	client.Transport.(*http.Transport).TLSClientConfig.RootCAs = x509.NewCertPool()
}

type muxOption func(mux *http.ServeMux)

func withResponseForPath(t *testing.T, path string, response []byte) muxOption {
	t.Helper()

	return func(mux *http.ServeMux) {
		mux.HandleFunc(path, func(w http.ResponseWriter, req *http.Request) {
			t.Logf("server handling request: %s %s", req.Method, req.URL)

			_, err := w.Write(response)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

var testID = clio.Identification{
	Name:    "test-app",
	Version: "v0.5.3",
}

func newTestServer(t *testing.T, muxOptions ...muxOption) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	for _, option := range muxOptions {
		option(mux)
	}

	server := httptest.NewTLSServer(mux)
	t.Logf("new TLS server listening at %s", getHost(t, server))

	return server
}

func createRequestURL(t *testing.T, server *httptest.Server, path string) string {
	t.Helper()

	// TODO: Figure out how to get this value from the server without hardcoding it here
	const testServerCertificateName = "example.com"

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	// Set URL hostname to value from TLS certificate
	serverURL.Host = fmt.Sprintf("%s:%s", testServerCertificateName, serverURL.Port())

	serverURL.Path = path

	return serverURL.String()
}

// getClient returns an http.Client that can be used to contact the test TLS server.
func getClient(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()

	httpClient := server.Client()
	transport := httpClient.Transport.(*http.Transport)

	serverHost := getHost(t, server)

	transport.DialContext = func(_ context.Context, _, addr string) (net.Conn, error) {
		t.Logf("client dialing %q for host %q", serverHost, addr)

		// Ensure the client dials our test server
		return net.Dial("tcp", serverHost)
	}

	return httpClient
}

// getHost extracts the host value from a server URL string.
// e.g. given a server with URL "http://1.2.3.4:5000/foo", getHost returns "1.2.3.4:5000"
func getHost(t *testing.T, server *httptest.Server) string {
	t.Helper()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	return u.Hostname() + ":" + u.Port()
}

var testFileContent = []byte("This is the content of a test file!\n")
