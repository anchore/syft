package sbomsync

import (
	"testing"

	"github.com/magiconair/properties/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func TestNewBuilder(t *testing.T) {
	tests := []struct {
		name string
		sbom sbom.SBOM
	}{
		{
			"TestNewBuilder with empty sbom",
			sbom.SBOM{
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewBuilder(&tt.sbom)
			builder.AddPackages(pkg.Package{})
			accessor := builder.(Accessor)
			accessor.ReadFromSBOM(func(s *sbom.SBOM) {
				packageCount := s.Artifacts.Packages.PackageCount()
				assert.Equal(t, packageCount, 1, "expected 1 package in sbom")
			})
		})
	}
}

func Test_sbomBuilder_DeletePackages(t *testing.T) {
	testPackage := pkg.Package{
		Name:    "test",
		Version: "1.0.0",
		Type:    pkg.DebPkg,
	}
	testPackage.SetID()

	keepMe := pkg.Package{
		Name:    "keepMe",
		Version: "1.0.0",
		Type:    pkg.DebPkg,
	}

	prexistingRelationships := []artifact.Relationship{
		{
			From: testPackage,
			To:   testPackage,
			Type: artifact.DependencyOfRelationship,
		},
	}

	tests := []struct {
		name string
		sbom sbom.SBOM
	}{
		{
			"Test_sbomBuilder_DeletePackages deletes a given package",
			sbom.SBOM{
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewBuilder(&tt.sbom)
			builder.AddPackages(testPackage, keepMe)
			accessor := builder.(Accessor)
			accessor.WriteToSBOM(func(s *sbom.SBOM) {
				s.Relationships = prexistingRelationships
			})

			builder.DeletePackages(testPackage.ID())
			newAccess := builder.(Accessor)
			newAccess.ReadFromSBOM(func(s *sbom.SBOM) {
				packageCount := s.Artifacts.Packages.PackageCount()

				// deleted target package
				assert.Equal(t, packageCount, 1, "expected 1 packages in sbom")
				relationshipCount := len(s.Relationships)

				// deleted relationships that reference the deleted package
				assert.Equal(t, relationshipCount, 0, "expected 0 relationships in sbom")
			})
		})
	}
}
