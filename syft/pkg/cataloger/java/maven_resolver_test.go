package java

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/stretchr/testify/require"
	"github.com/vifraa/gopom"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/internal/fileresolver"
)

func Test_resolveProperty(t *testing.T) {
	tests := []struct {
		name     string
		property string
		pom      gopom.Project
		expected string
	}{
		{
			name:     "property",
			property: "${version.number}",
			pom: gopom.Project{
				Properties: &gopom.Properties{
					Entries: map[string]string{
						"version.number": "12.5.0",
					},
				},
			},
			expected: "12.5.0",
		},
		{
			name:     "groupId",
			property: "${project.groupId}",
			pom: gopom.Project{
				GroupID: ptr("org.some.group"),
			},
			expected: "org.some.group",
		},
		{
			name:     "parent groupId",
			property: "${project.parent.groupId}",
			pom: gopom.Project{
				Parent: &gopom.Parent{
					GroupID: ptr("org.some.parent"),
				},
			},
			expected: "org.some.parent",
		},
		{
			name:     "nil pointer halts search",
			property: "${project.parent.groupId}",
			pom: gopom.Project{
				Parent: nil,
			},
			expected: "",
		},
		{
			name:     "nil string pointer halts search",
			property: "${project.parent.groupId}",
			pom: gopom.Project{
				Parent: &gopom.Parent{
					GroupID: nil,
				},
			},
			expected: "",
		},
		{
			name:     "double dereference",
			property: "${springboot.version}",
			pom: gopom.Project{
				Parent: &gopom.Parent{
					Version: ptr("1.2.3"),
				},
				Properties: &gopom.Properties{
					Entries: map[string]string{
						"springboot.version": "${project.parent.version}",
					},
				},
			},
			expected: "1.2.3",
		},
		{
			name:     "map missing stops double dereference",
			property: "${springboot.version}",
			pom: gopom.Project{
				Parent: &gopom.Parent{
					Version: ptr("1.2.3"),
				},
			},
			expected: "",
		},
		{
			name:     "resolution halts even if it resolves to a variable",
			property: "${springboot.version}",
			pom: gopom.Project{
				Parent: &gopom.Parent{
					Version: ptr("${undefined.version}"),
				},
				Properties: &gopom.Properties{
					Entries: map[string]string{
						"springboot.version": "${project.parent.version}",
					},
				},
			},
			expected: "",
		},
		{
			name:     "resolution halts even if cyclic",
			property: "${springboot.version}",
			pom: gopom.Project{
				Properties: &gopom.Properties{
					Entries: map[string]string{
						"springboot.version": "${springboot.version}",
					},
				},
			},
			expected: "",
		},
		{
			name:     "resolution halts even if cyclic more steps",
			property: "${cyclic.version}",
			pom: gopom.Project{
				Properties: &gopom.Properties{
					Entries: map[string]string{
						"other.version":      "${cyclic.version}",
						"springboot.version": "${other.version}",
						"cyclic.version":     "${springboot.version}",
					},
				},
			},
			expected: "",
		},
		{
			name:     "resolution halts even if cyclic involving parent",
			property: "${cyclic.version}",
			pom: gopom.Project{
				Parent: &gopom.Parent{
					Version: ptr("${cyclic.version}"),
				},
				Properties: &gopom.Properties{
					Entries: map[string]string{
						"other.version":      "${parent.version}",
						"springboot.version": "${other.version}",
						"cyclic.version":     "${springboot.version}",
					},
				},
			},
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := newMavenResolver(nil, DefaultArchiveCatalogerConfig())
			resolved := r.getPropertyValue(context.Background(), ptr(test.property), &test.pom)
			require.Equal(t, test.expected, resolved)
		})
	}
}

func Test_mavenResolverLocal(t *testing.T) {
	dir, err := filepath.Abs("test-fixtures/pom/maven-repo")
	require.NoError(t, err)

	tests := []struct {
		name       string
		groupID    string
		artifactID string
		version    string
		maxDepth   int
		expression string
		expected   string
		wantErr    require.ErrorAssertionFunc
	}{
		{
			name:       "artifact id with variable from 2nd parent",
			groupID:    "my.org",
			artifactID: "child-one",
			version:    "1.3.6",
			expression: "${project.one}",
			expected:   "1",
		},
		{
			name:       "depth limited large enough",
			groupID:    "my.org",
			artifactID: "child-one",
			version:    "1.3.6",
			expression: "${project.one}",
			expected:   "1",
			maxDepth:   2,
		},
		{
			name:       "depth limited should not resolve",
			groupID:    "my.org",
			artifactID: "child-one",
			version:    "1.3.6",
			expression: "${project.one}",
			expected:   "",
			maxDepth:   1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			r := newMavenResolver(nil, ArchiveCatalogerConfig{
				UseNetwork:              false,
				UseMavenLocalRepository: true,
				MavenLocalRepositoryDir: dir,
				MaxParentRecursiveDepth: test.maxDepth,
			})
			pom, err := r.findPom(ctx, test.groupID, test.artifactID, test.version)
			if test.wantErr != nil {
				test.wantErr(t, err)
			} else {
				require.NoError(t, err)
			}
			got := r.getPropertyValue(context.Background(), &test.expression, pom)
			require.Equal(t, test.expected, got)
		})
	}
}

func Test_mavenResolverRemote(t *testing.T) {
	url := mockMavenRepo(t)

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
			r := newMavenResolver(nil, ArchiveCatalogerConfig{
				UseNetwork:              true,
				UseMavenLocalRepository: false,
				MavenBaseURL:            url,
			})
			pom, err := r.findPom(ctx, test.groupID, test.artifactID, test.version)
			if test.wantErr != nil {
				test.wantErr(t, err)
			} else {
				require.NoError(t, err)
			}
			got := r.getPropertyValue(context.Background(), &test.expression, pom)
			require.Equal(t, test.expected, got)
		})
	}
}

func Test_relativePathParent(t *testing.T) {
	resolver, err := fileresolver.NewFromDirectory("test-fixtures/pom/local", "")
	require.NoError(t, err)

	r := newMavenResolver(resolver, DefaultArchiveCatalogerConfig())
	locs, err := resolver.FilesByPath("child-1/pom.xml")
	require.NoError(t, err)
	require.Len(t, locs, 1)

	loc := locs[0]
	contents, err := resolver.FileContentsByLocation(loc)
	require.NoError(t, err)
	defer internal.CloseAndLogError(contents, loc.RealPath)

	pom, err := decodePomXML(contents)
	require.NoError(t, err)

	r.pomLocations[pom] = loc

	ctx := context.Background()
	parent, err := r.resolveParent(ctx, pom)
	require.NoError(t, err)
	require.Contains(t, r.pomLocations, parent)

	parent, err = r.resolveParent(ctx, parent)
	require.NoError(t, err)
	require.Contains(t, r.pomLocations, parent)

	got := r.getPropertyValue(ctx, ptr("${commons-exec_subversion}"), pom)
	require.Equal(t, "3", got)
}

// mockMavenRepo starts a remote maven repo serving all the pom files found in test-fixtures/pom/maven-repo
func mockMavenRepo(t *testing.T) (url string) {
	t.Helper()

	return mockMavenRepoAt(t, "test-fixtures/pom/maven-repo")
}

// mockMavenRepoAt starts a remote maven repo serving all the pom files found in the given directory
func mockMavenRepoAt(t *testing.T, dir string) (url string) {
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

func mockMavenHandler(responseFixture string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
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
