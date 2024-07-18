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
	"github.com/vifraa/gopom"
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
			r := newMavenResolver(DefaultArchiveCatalogerConfig())
			resolved := r.getPropertyValue(context.Background(), &test.pom, ptr(test.property))
			require.Equal(t, test.expected, resolved)
		})
	}
}

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
