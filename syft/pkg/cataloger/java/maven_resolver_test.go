package java

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/stretchr/testify/require"
)

func Test_mavenResolverLocal(t *testing.T) {
	dir, err := filepath.Abs("test-fixtures/pom/maven-repo")
	require.NoError(t, err)

	tests := []struct {
		groupID    string
		artifactID string
		version    string
		expression string
		expected   string
		wantErr    require.ErrorAssertionFunc
	}{
		{
			groupID:    "my.org",
			artifactID: "child-one",
			version:    "1.3.6",
			expression: "${project.one}",
			expected:   "1",
		},
	}

	for _, test := range tests {
		t.Run(test.artifactID, func(t *testing.T) {
			ctx := context.Background()
			r := newMavenResolver(ArchiveCatalogerConfig{
				UseNetwork:              false,
				UseMavenLocalRepository: true,
				MavenLocalRepositoryDir: dir,
				MaxParentRecursiveDepth: 5,
			})
			pom, err := r.findPom(ctx, test.groupID, test.artifactID, test.version)
			if test.wantErr != nil {
				test.wantErr(t, err)
			} else {
				require.NoError(t, err)
			}
			got := r.getPropertyValue(context.Background(), pom, &test.expression)
			require.Equal(t, test.expected, got)
		})
	}
}

func Test_mavenResolverRemote(t *testing.T) {
	url := testRepo(t, "test-fixtures/pom/maven-repo")

	tests := []struct {
		groupID    string
		artifactID string
		version    string
		expression string
		expected   string
		wantErr    require.ErrorAssertionFunc
	}{
		{
			groupID:    "my.org",
			artifactID: "child-one",
			version:    "1.3.6",
			expression: "${project.one}",
			expected:   "1",
		},
	}

	for _, test := range tests {
		t.Run(test.artifactID, func(t *testing.T) {
			ctx := context.Background()
			r := newMavenResolver(ArchiveCatalogerConfig{
				UseNetwork:              true,
				UseMavenLocalRepository: false,
				MavenBaseURL:            url,
				MaxParentRecursiveDepth: 5,
			})
			pom, err := r.findPom(ctx, test.groupID, test.artifactID, test.version)
			if test.wantErr != nil {
				test.wantErr(t, err)
			} else {
				require.NoError(t, err)
			}
			got := r.getPropertyValue(context.Background(), pom, &test.expression)
			require.Equal(t, test.expected, got)
		})
	}
}

// testRepo starts a remote maven repo serving all the pom files found in the given directory
func testRepo(t *testing.T, dir string) (url string) {
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
		mux.HandleFunc(match, generateMockMavenHandler(fullPath))
	}

	return server.URL
}
