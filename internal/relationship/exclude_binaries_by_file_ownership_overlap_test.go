package relationship

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

func TestExcludeByFileOwnershipOverlap(t *testing.T) {
	packageA := pkg.Package{Name: "package-a", Type: pkg.ApkPkg}
	packageB := pkg.Package{Name: "package-b", Type: pkg.BinaryPkg, Metadata: pkg.JavaVMInstallation{}}
	packageC := pkg.Package{Name: "package-c", Type: pkg.BinaryPkg, Metadata: pkg.ELFBinaryPackageNoteJSONPayload{Type: "rpm"}}
	for _, p := range []*pkg.Package{&packageA, &packageB, &packageC} {
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
			// prove that OS -> bin exclusions are wired
			name: "exclusions from os -> elf binary (as RPM)",
			relationship: artifact.Relationship{
				Type: artifact.OwnershipByFileOverlapRelationship,
				From: packageA, // OS
				To:   packageC, // ELF binary
			},
			packages:      pkg.NewCollection(packageA, packageC),
			shouldExclude: true,
		},
		{
			// prove that bin -> JVM exclusions are wired
			name: "exclusions from binary -> binary with JVM metadata",
			relationship: artifact.Relationship{
				Type: artifact.OwnershipByFileOverlapRelationship,
				From: packageB, // binary with JVM metadata
				To:   packageC, // binary
			},
			packages:      pkg.NewCollection(packageC, packageB),
			shouldExclude: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualExclude := excludeByFileOwnershipOverlap(test.relationship, test.packages)
			didExclude := actualExclude != ""
			if !didExclude && test.shouldExclude {
				t.Errorf("expected to exclude relationship %+v", test.relationship)
			}
		})

	}
}

func TestIdentifyOverlappingOSRelationship(t *testing.T) {
	packageA := pkg.Package{Name: "package-a", Type: pkg.ApkPkg} // OS package
	packageB := pkg.Package{Name: "package-b", Type: pkg.BinaryPkg}
	packageC := pkg.Package{Name: "package-c", Type: pkg.BinaryPkg, Metadata: pkg.BinarySignature{}}
	packageD := pkg.Package{Name: "package-d", Type: pkg.PythonPkg} // Language package
	packageE := pkg.Package{Name: "package-e", Type: pkg.BinaryPkg, Metadata: pkg.ELFBinaryPackageNoteJSONPayload{}}

	for _, p := range []*pkg.Package{&packageA, &packageB, &packageC, &packageD, &packageE} {
		p.SetID()
	}

	tests := []struct {
		name       string
		parent     *pkg.Package
		child      *pkg.Package
		expectedID artifact.ID
	}{
		{
			name:       "OS -> binary without metadata",
			parent:     &packageA,
			child:      &packageB,
			expectedID: packageB.ID(), // OS package to binary package, should return child ID
		},
		{
			name:       "OS -> binary with binary metadata",
			parent:     &packageA,
			child:      &packageC,
			expectedID: packageC.ID(), // OS package to binary package with binary metadata, should return child ID
		},
		{
			name:       "OS -> non-binary package",
			parent:     &packageA,
			child:      &packageD,
			expectedID: "", // OS package to non-binary package, no exclusion
		},
		{
			name:       "OS -> binary with ELF metadata",
			parent:     &packageA,
			child:      &packageE,
			expectedID: packageE.ID(), // OS package to binary package with ELF metadata, should return child ID
		},
		{
			name:       "non-OS parent",
			parent:     &packageD, // non-OS package
			child:      &packageC,
			expectedID: "", // non-OS parent, no exclusion
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resultID := identifyOverlappingOSRelationship(tt.parent, tt.child)
			assert.Equal(t, tt.expectedID, resultID)
		})
	}
}

func TestIdentifyOverlappingJVMRelationship(t *testing.T) {

	packageA := pkg.Package{Name: "package-a", Type: pkg.BinaryPkg}
	packageB := pkg.Package{Name: "package-b", Type: pkg.BinaryPkg, Metadata: pkg.BinarySignature{}}
	packageC := pkg.Package{Name: "package-c", Type: pkg.BinaryPkg, Metadata: pkg.JavaVMInstallation{}}
	packageD := pkg.Package{Name: "package-d", Type: pkg.PythonPkg}
	packageE := pkg.Package{Name: "package-e", Type: pkg.BinaryPkg}

	for _, p := range []*pkg.Package{&packageA, &packageB, &packageC, &packageD, &packageE} {
		p.SetID()
	}

	tests := []struct {
		name       string
		parent     *pkg.Package
		child      *pkg.Package
		expectedID artifact.ID
	}{
		{
			name:       "binary -> binary with JVM installation",
			parent:     &packageA,
			child:      &packageC,
			expectedID: packageA.ID(), // JVM found, return BinaryPkg ID
		},
		{
			name:       "binary -> binary with binary signature",
			parent:     &packageA,
			child:      &packageB,
			expectedID: "", // binary signatures only found, no exclusion
		},
		{
			name:       "binary -> python (non-binary child)",
			parent:     &packageA,
			child:      &packageD,
			expectedID: "", // non-binary child, no exclusion
		},
		{
			name:       "no JVM or signature in binary -> binary",
			parent:     &packageA,
			child:      &packageE,
			expectedID: "", // no JVM or binary signature, no exclusion
		},
		{
			name:       "non-binary parent",
			parent:     &packageD,
			child:      &packageC,
			expectedID: "", // non-binary parent, no exclusion
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resultID := identifyOverlappingJVMRelationship(tt.parent, tt.child)
			assert.Equal(t, tt.expectedID, resultID)
		})
	}
}
