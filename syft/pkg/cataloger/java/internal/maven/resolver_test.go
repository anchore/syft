package maven

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/internal/fileresolver"
	maventest "github.com/anchore/syft/syft/pkg/cataloger/java/internal/maven/test"
)

func Test_resolveProperty(t *testing.T) {
	tests := []struct {
		name     string
		property string
		pom      Project
		expected string
	}{
		{
			name:     "property",
			property: "${version.number}",
			pom: Project{
				Properties: &Properties{
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
			pom: Project{
				GroupID: ptr("org.some.group"),
			},
			expected: "org.some.group",
		},
		{
			name:     "parent groupId",
			property: "${project.parent.groupId}",
			pom: Project{
				Parent: &Parent{
					GroupID: ptr("org.some.parent"),
				},
			},
			expected: "org.some.parent",
		},
		{
			name:     "nil pointer halts search",
			property: "${project.parent.groupId}",
			pom: Project{
				Parent: nil,
			},
			expected: "",
		},
		{
			name:     "nil string pointer halts search",
			property: "${project.parent.groupId}",
			pom: Project{
				Parent: &Parent{
					GroupID: nil,
				},
			},
			expected: "",
		},
		{
			name:     "double dereference",
			property: "${springboot.version}",
			pom: Project{
				Parent: &Parent{
					Version: ptr("1.2.3"),
				},
				Properties: &Properties{
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
			pom: Project{
				Parent: &Parent{
					Version: ptr("1.2.3"),
				},
			},
			expected: "",
		},
		{
			name:     "resolution halts even if it resolves to a variable",
			property: "${springboot.version}",
			pom: Project{
				Parent: &Parent{
					Version: ptr("${undefined.version}"),
				},
				Properties: &Properties{
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
			pom: Project{
				Properties: &Properties{
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
			pom: Project{
				Properties: &Properties{
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
			pom: Project{
				Parent: &Parent{
					Version: ptr("${cyclic.version}"),
				},
				Properties: &Properties{
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
			r := NewResolver(nil, DefaultConfig())
			resolved := r.ResolveProperty(context.Background(), &test.pom, ptr(test.property))
			require.Equal(t, test.expected, resolved)
		})
	}
}

func Test_mavenResolverLocal(t *testing.T) {
	dir, err := filepath.Abs("test-fixtures/maven-repo")
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
			r := NewResolver(nil, Config{
				UseNetwork:              false,
				UseLocalRepository:      true,
				LocalRepositoryDir:      dir,
				MaxParentRecursiveDepth: test.maxDepth,
			})
			pom, err := r.FindPom(ctx, test.groupID, test.artifactID, test.version)
			if test.wantErr != nil {
				test.wantErr(t, err)
			} else {
				require.NoError(t, err)
			}
			got := r.ResolveProperty(context.Background(), pom, &test.expression)
			require.Equal(t, test.expected, got)
		})
	}
}

func Test_mavenResolverRemote(t *testing.T) {
	url := maventest.MockRepo(t, "test-fixtures/maven-repo")

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
		{
			groupID:    "my.org", // this particular package has a circular reference
			artifactID: "circular",
			version:    "1.2.3",
			expression: "${unresolved}",
			expected:   "",
		},
	}

	for _, test := range tests {
		t.Run(test.artifactID, func(t *testing.T) {
			ctx := context.Background()
			r := NewResolver(nil, Config{
				UseNetwork:         true,
				UseLocalRepository: false,
				Repositories:       strings.Split(url, ","),
			})
			pom, err := r.FindPom(ctx, test.groupID, test.artifactID, test.version)
			if test.wantErr != nil {
				test.wantErr(t, err)
			} else {
				require.NoError(t, err)
			}
			got := r.ResolveProperty(context.Background(), pom, &test.expression)
			require.Equal(t, test.expected, got)
		})
	}
}

func Test_relativePathParent(t *testing.T) {
	resolver, err := fileresolver.NewFromDirectory("test-fixtures/local", "")
	require.NoError(t, err)

	ctx := context.Background()

	tests := []struct {
		name     string
		pom      string
		validate func(t *testing.T, r *Resolver, pom *Project)
	}{
		{
			name: "basic",
			pom:  "child-1/pom.xml",
			validate: func(t *testing.T, r *Resolver, pom *Project) {
				parent, err := r.resolveParent(ctx, pom)
				require.NoError(t, err)
				require.Contains(t, r.pomLocations, parent)

				parent, err = r.resolveParent(ctx, parent)
				require.NoError(t, err)
				require.Contains(t, r.pomLocations, parent)

				got := r.ResolveProperty(ctx, pom, ptr("${commons-exec_subversion}"))
				require.Equal(t, "3", got)
			},
		},
		{
			name: "parent property",
			pom:  "child-2/pom.xml",
			validate: func(t *testing.T, r *Resolver, pom *Project) {
				id := r.ResolveID(ctx, pom)
				// child.parent.version = ${revision}
				// parent.revision = 3.3.3
				require.Equal(t, id.Version, "3.3.3")
			},
		},
		{
			name: "invalid parent",
			pom:  "child-3/pom.xml",
			validate: func(t *testing.T, r *Resolver, pom *Project) {
				require.NotNil(t, pom)
				id := r.ResolveID(ctx, pom)
				// version should not be resolved to anything
				require.Equal(t, "", id.Version)
			},
		},
		{
			name: "circular resolving ID variables",
			pom:  "circular-1/pom.xml",
			validate: func(t *testing.T, r *Resolver, pom *Project) {
				require.NotNil(t, pom)
				id := r.ResolveID(ctx, pom)
				// version should be resolved, but not artifactId
				require.Equal(t, "1.2.3", id.Version)
				require.Equal(t, "", id.ArtifactID)
			},
		},
		{
			name: "circular parent only",
			pom:  "circular-2/pom.xml",
			validate: func(t *testing.T, r *Resolver, pom *Project) {
				require.NotNil(t, pom)
				id := r.ResolveID(ctx, pom)
				require.Equal(t, "", id.Version)
				require.Equal(t, "something", id.ArtifactID)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := NewResolver(resolver, DefaultConfig())
			locs, err := resolver.FilesByPath(test.pom)
			require.NoError(t, err)
			require.Len(t, locs, 1)

			loc := locs[0]
			contents, err := resolver.FileContentsByLocation(loc)
			require.NoError(t, err)
			defer internal.CloseAndLogError(contents, loc.RealPath)

			pom, err := ParsePomXML(contents)
			require.NoError(t, err)

			r.pomLocations[pom] = loc

			test.validate(t, r, pom)
		})
	}
}

// ptr returns a pointer to the given value
func ptr[T any](value T) *T {
	return &value
}
