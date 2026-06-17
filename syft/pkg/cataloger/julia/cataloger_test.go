package julia

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_PackageCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain manifest files",
			fixture: "testdata/glob-paths",
			expected: []string{
				"Manifest.toml",
				"Manifest-v1.11.toml",
				"Project.toml",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewPackageCataloger(DefaultCatalogerConfig()))
		})
	}
}

func TestPackageCatalogerMergesMultipleManifests(t *testing.T) {
	fixture := "testdata/multiple-manifests"
	cataloger := NewPackageCataloger(DefaultCatalogerConfig())

	pkgtest.NewCatalogTester().
		FromDirectory(t, fixture).
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
			if len(pkgs) != 6 {
				t.Fatalf("expected 6 packages, got %d", len(pkgs))
			}

			versionsByName := make(map[string][]string)
			duplicateLocationCounts := make(map[int]int)
			parentDependsRelationships := 0
			for _, p := range pkgs {
				versionsByName[p.Name] = append(versionsByName[p.Name], p.Version)
				if p.Name == "Duplicate" && p.Version == "1.0.0" {
					duplicateLocationCounts[len(p.Locations.ToSlice())]++
				}
			}
			for _, r := range relationships {
				from, fromOK := r.From.(pkg.Package)
				to, toOK := r.To.(pkg.Package)
				if !fromOK || !toOK {
					continue
				}
				if from.Name == "Duplicate" && to.Name == "ParentDepends" {
					parentDependsRelationships++
					if len(from.Locations.ToSlice()) != 2 {
						t.Errorf("expected ParentDepends to resolve to root Duplicate package, got dependency from %v", from.Locations.ToSlice())
					}
				}
			}

			// Yes this is an exact duplicate, but it's in two different manifests with different project files so we
			// can't merge them as they are in separate projects
			if len(versionsByName["Duplicate"]) != 2 {
				t.Errorf("expected root and child Duplicate@1.0.0 packages, got %v", versionsByName["Duplicate"])
			}
			if duplicateLocationCounts[2] != 1 {
				t.Errorf("expected root Duplicate@1.0.0 to retain both manifest locations, got counts %v", duplicateLocationCounts)
			}
			if duplicateLocationCounts[1] != 1 {
				t.Errorf("expected child Duplicate@1.0.0 to remain separate, got counts %v", duplicateLocationCounts)
			}
			if len(versionsByName["ParentDepends"]) != 1 {
				t.Errorf("expected one ParentDepends@1.0.0 package, got %v", versionsByName["ParentDepends"])
			}
			if parentDependsRelationships != 1 {
				t.Errorf("expected exactly one root Duplicate -> ParentDepends relationship, got %d", parentDependsRelationships)
			}
			if len(versionsByName["MultiVersion"]) != 2 {
				t.Errorf("expected both MultiVersion packages, got %v", versionsByName["MultiVersion"])
			}
			if len(versionsByName["VersionSpecific"]) != 1 || versionsByName["VersionSpecific"][0] != "1.0.0" {
				t.Errorf("expected VersionSpecific@1.0.0 from version-specific manifest, got %v", versionsByName["VersionSpecific"])
			}
		}).
		TestCataloger(t, cataloger)
}
