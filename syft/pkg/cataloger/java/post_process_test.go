package java

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func TestBuildPackageIndex(t *testing.T) {
	p1 := pkg.Package{
		Name:    "dep-a",
		Version: "1.0",
		Type:    pkg.JavaPkg,
		Metadata: pkg.JavaArchive{
			PomProperties: &pkg.JavaPomProperties{
				GroupID:    "com.example",
				ArtifactID: "dep-a",
				Version:    "1.0",
			},
		},
	}

	p2 := pkg.Package{
		Name:    "dep-b",
		Version: "2.0",
		Type:    pkg.JavaPkg,
		Metadata: pkg.JavaArchive{
			PomProperties: &pkg.JavaPomProperties{
				GroupID:    "org.other",
				ArtifactID: "dep-b",
				Version:    "2.0",
			},
		},
	}

	packages := []pkg.Package{p1, p2}
	index := buildPackageIndex(packages)

	// full ID lookup
	assert.NotNil(t, index["com.example:dep-a:1.0"])
	assert.NotNil(t, index["org.other:dep-b:2.0"])

	// partial lookup
	assert.NotNil(t, index["com.example:dep-a"])
	assert.NotNil(t, index["org.other:dep-b"])

	// artifact-only lookup
	assert.NotNil(t, index["dep-a"])
	assert.NotNil(t, index["dep-b"])
}

func TestFindPackageByMavenID(t *testing.T) {
	p := pkg.Package{
		Name:    "my-lib",
		Version: "3.0",
		Type:    pkg.JavaPkg,
		Metadata: pkg.JavaArchive{
			PomProperties: &pkg.JavaPomProperties{
				GroupID:    "com.example",
				ArtifactID: "my-lib",
				Version:    "3.0",
			},
		},
	}

	packages := []pkg.Package{p}
	index := buildPackageIndex(packages)

	tests := []struct {
		name  string
		id    string
		found bool
	}{
		{name: "exact match", id: "com.example:my-lib:3.0", found: true},
		{name: "group:artifact match", id: "com.example:my-lib:9.9", found: true},
		{name: "artifact only match", id: "org.different:my-lib:1.0", found: true},
		{name: "no match", id: "com.example:other-lib:1.0", found: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findPackageByMavenID(index, tt.id)
			if tt.found {
				require.NotNil(t, result)
				assert.Equal(t, "my-lib", result.Name)
			} else {
				assert.Nil(t, result)
			}
		})
	}
}

func TestExtractMavenIDString(t *testing.T) {
	tests := []struct {
		name     string
		pkg      *pkg.Package
		expected string
	}{
		{
			name: "from pom properties",
			pkg: &pkg.Package{
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						GroupID:    "com.example",
						ArtifactID: "my-lib",
						Version:    "1.0",
					},
				},
			},
			expected: "com.example:my-lib:1.0",
		},
		{
			name: "from pom project",
			pkg: &pkg.Package{
				Metadata: pkg.JavaArchive{
					PomProject: &pkg.JavaPomProject{
						GroupID:    "org.other",
						ArtifactID: "other-lib",
						Version:    "2.0",
					},
				},
			},
			expected: "org.other:other-lib:2.0",
		},
		{
			name: "pom properties preferred over pom project",
			pkg: &pkg.Package{
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						GroupID:    "com.props",
						ArtifactID: "props-lib",
						Version:    "1.0",
					},
					PomProject: &pkg.JavaPomProject{
						GroupID:    "com.project",
						ArtifactID: "project-lib",
						Version:    "2.0",
					},
				},
			},
			expected: "com.props:props-lib:1.0",
		},
		{
			name:     "nil package",
			pkg:      nil,
			expected: "",
		},
		{
			name: "no java metadata",
			pkg: &pkg.Package{
				Metadata: nil,
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractMavenIDString(tt.pkg))
		})
	}
}

func TestExtractGroupArtifact(t *testing.T) {
	assert.Equal(t, "com.example:my-lib", extractGroupArtifact("com.example:my-lib:1.0"))
	assert.Equal(t, "com.example:my-lib", extractGroupArtifact("com.example:my-lib"))
	assert.Equal(t, "", extractGroupArtifact(""))
	assert.Equal(t, "", extractGroupArtifact("single"))
}

func TestExtractArtifactIDFromCoord(t *testing.T) {
	assert.Equal(t, "my-lib", extractArtifactIDFromCoord("com.example:my-lib:1.0"))
	assert.Equal(t, "my-lib", extractArtifactIDFromCoord("com.example:my-lib"))
	assert.Equal(t, "", extractArtifactIDFromCoord("single"))
	assert.Equal(t, "", extractArtifactIDFromCoord(""))
}

func TestResolveHierarchicalDependencies_Disabled(t *testing.T) {
	// should be a no-op when feature is disabled
	cfg := DefaultArchiveCatalogerConfig()
	cfg.UseEmbeddedPOMDependencies = false

	accessor := &mockAccessor{
		relationships: []artifact.Relationship{
			{
				From: pkg.Package{Name: "child"},
				To:   pkg.Package{Name: "wrong-parent"},
				Type: artifact.DependencyOfRelationship,
				Data: NewDependencyRelationshipDataWithParent(1, "", "com.example:real-parent:1.0"),
			},
		},
	}

	ResolveHierarchicalDependencies(accessor, cfg)

	// relationship should be unchanged
	assert.Equal(t, "wrong-parent", accessor.relationships[0].To.(pkg.Package).Name)
}

func TestResolveHierarchicalDependencies_ResolvesParent(t *testing.T) {
	parent := pkg.Package{
		Name:    "real-parent",
		Version: "1.0",
		Type:    pkg.JavaPkg,
		Metadata: pkg.JavaArchive{
			PomProperties: &pkg.JavaPomProperties{
				GroupID:    "com.example",
				ArtifactID: "real-parent",
				Version:    "1.0",
			},
		},
	}
	parent.SetID()

	child := pkg.Package{
		Name:    "child",
		Version: "2.0",
		Type:    pkg.JavaPkg,
		Metadata: pkg.JavaArchive{
			PomProperties: &pkg.JavaPomProperties{
				GroupID:    "com.example",
				ArtifactID: "child",
				Version:    "2.0",
			},
		},
	}
	child.SetID()

	placeholder := pkg.Package{Name: "placeholder"}
	placeholder.SetID()

	cfg := DefaultArchiveCatalogerConfig()
	cfg.UseEmbeddedPOMDependencies = true

	accessor := &mockAccessor{
		packages: []pkg.Package{parent, child, placeholder},
		relationships: []artifact.Relationship{
			{
				From: child,
				To:   placeholder,
				Type: artifact.DependencyOfRelationship,
				Data: NewDependencyRelationshipDataWithParent(1, "compile", "com.example:real-parent:1.0"),
			},
		},
	}

	ResolveHierarchicalDependencies(accessor, cfg)

	// relationship should now point to real-parent
	resolvedTo, ok := accessor.relationships[0].To.(pkg.Package)
	require.True(t, ok)
	assert.Equal(t, "real-parent", resolvedTo.Name)

	// IntendedParentID should be cleared
	data, ok := accessor.relationships[0].Data.(DependencyRelationshipData)
	require.True(t, ok)
	assert.Empty(t, data.IntendedParentID)
	assert.Equal(t, "compile", data.Scope)
}

// mockAccessor implements sbomsync.Accessor for testing
type mockAccessor struct {
	packages      []pkg.Package
	relationships []artifact.Relationship
}

func (m *mockAccessor) ReadFromSBOM(fn func(*sbom.SBOM)) {
	s := &sbom.SBOM{
		Relationships: m.relationships,
	}
	s.Artifacts.Packages = pkg.NewCollection(m.packages...)
	fn(s)
}

func (m *mockAccessor) WriteToSBOM(fn func(*sbom.SBOM)) {
	s := &sbom.SBOM{
		Relationships: m.relationships,
	}
	s.Artifacts.Packages = pkg.NewCollection(m.packages...)
	fn(s)
	m.relationships = s.Relationships
}
