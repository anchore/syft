package maventest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal"
)

// MockRepo starts a remote maven repo serving all the pom files found in a maven-structured directory
func MockRepo(t *testing.T, dir string) (url string) {
	t.Helper()

	// mux is the HTTP request multiplexer used with the test server.
	mux := http.NewServeMux()

	// We want to ensure that tests catch mistakes where the endpoint URL is
	// specified as absolute rather than relative. It only makes a difference
	// when there's a non-empty base URL path. So, use that. See issue #752.
	apiHandler := http.NewServeMux()
	apiHandler.Handle("/", mux)
	// server is a test HTTP server used to provide mock API responses.
	server := httptest.NewServer(apiHandler)

	t.Cleanup(server.Close)

	matches, err := doublestar.Glob(os.DirFS(dir), filepath.Join("**", "*.pom"))
	require.NoError(t, err)

	for _, match := range matches {
		fullPath, err := filepath.Abs(filepath.Join(dir, match))
		require.NoError(t, err)
		match = "/" + filepath.ToSlash(match)
		mux.HandleFunc(match, mockMavenHandler(fullPath))
	}

	return server.URL
}

func mockMavenHandler(responseFixture string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Set the Content-Type header to indicate that the response is XML
		w.Header().Set("Content-Type", "application/xml")
		// Copy the file's content to the response writer
		f, err := os.Open(responseFixture)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer internal.CloseAndLogError(f, responseFixture)
		_, err = io.Copy(w, f)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}
