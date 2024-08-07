package relationship

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

func TestExclude(t *testing.T) {
	packageA := pkg.Package{Name: "package-a", Type: pkg.ApkPkg}
	packageB := pkg.Package{Name: "package-a", Type: pkg.PythonPkg}
	packageC := pkg.Package{Name: "package-a", Type: pkg.BinaryPkg}
	packageD := pkg.Package{Name: "package-d", Type: pkg.BinaryPkg}
	packageE := pkg.Package{Name: "package-e", Type: pkg.RpmPkg, Metadata: pkg.ELFBinaryPackageNoteJSONPayload{Type: "rpm"}}
	packageF := pkg.Package{Name: "package-f", Type: pkg.RpmPkg, Metadata: pkg.BinarySignature{}}
	for _, p := range []*pkg.Package{&packageA, &packageB, &packageC, &packageD, &packageE, &packageF} {
		p := p
		p.SetID()
	}

	tests := []struct {
		name          string
		relationship  artifact.Relationship
		packages      *pkg.Collection
		shouldExclude bool
	}{
		{
			name: "no exclusions from os -> python",
			relationship: artifact.Relationship{
				Type: artifact.OwnershipByFileOverlapRelationship,
				From: packageA,
				To:   packageB,
			},
			packages:      pkg.NewCollection(packageA, packageB),
			shouldExclude: false,
		},
		{
			name: "exclusions from os -> binary",
			relationship: artifact.Relationship{
				Type: artifact.OwnershipByFileOverlapRelationship,
				From: packageA,
				To:   packageC,
			},
			packages:      pkg.NewCollection(packageA, packageC),
			shouldExclude: true,
		},
		{
			name: "exclusions from os -> elf binary (as RPM)",
			relationship: artifact.Relationship{
				Type: artifact.OwnershipByFileOverlapRelationship,
				From: packageA,
				To:   packageE,
			},
			packages:      pkg.NewCollection(packageA, packageE),
			shouldExclude: true,
		},
		{
			name: "exclusions from os -> binary (masquerading as RPM)",
			relationship: artifact.Relationship{
				Type: artifact.OwnershipByFileOverlapRelationship,
				From: packageA,
				To:   packageF,
			},
			packages:      pkg.NewCollection(packageA, packageF),
			shouldExclude: true,
		},
		{
			name: "no exclusions from python -> binary",
			relationship: artifact.Relationship{
				Type: artifact.OwnershipByFileOverlapRelationship,
				From: packageB,
				To:   packageC,
			},
			packages:      pkg.NewCollection(packageB, packageC),
			shouldExclude: false,
		},
		{
			name: "no exclusions for different package names",
			relationship: artifact.Relationship{
				Type: artifact.OwnershipByFileOverlapRelationship,
				From: packageA,
				To:   packageD,
			},
			packages:      pkg.NewCollection(packageA, packageD),
			shouldExclude: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !excludeBinaryByFileOwnershipOverlap(test.relationship, test.packages) && test.shouldExclude {
				t.Errorf("expected to exclude relationship %+v", test.relationship)
			}
		})

	}
}
