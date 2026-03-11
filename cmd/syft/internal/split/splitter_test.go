package split

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func TestSplit(t *testing.T) {
	// create test coordinates
	coord1 := file.Coordinates{RealPath: "/lib/apk/db/installed", FileSystemID: "layer1"}
	coord2 := file.Coordinates{RealPath: "/usr/lib/libmusl.so", FileSystemID: "layer1"}
	coord3 := file.Coordinates{RealPath: "/unrelated/file", FileSystemID: "layer1"}

	// create test packages
	pkgA := pkg.Package{
		Name:      "alpine-baselayout",
		Version:   "3.2.0-r7",
		Type:      pkg.ApkPkg,
		Locations: file.NewLocationSet(file.NewLocationFromCoordinates(coord1)),
	}
	pkgA.SetID()

	pkgB := pkg.Package{
		Name:      "musl",
		Version:   "1.2.2-r0",
		Type:      pkg.ApkPkg,
		Locations: file.NewLocationSet(file.NewLocationFromCoordinates(coord2)),
	}
	pkgB.SetID()

	pkgC := pkg.Package{
		Name:      "unrelated",
		Version:   "1.0.0",
		Type:      pkg.ApkPkg,
		Locations: file.NewLocationSet(file.NewLocationFromCoordinates(coord3)),
	}
	pkgC.SetID()

	// create source SBOM with relationships
	sourceSBOM := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(pkgA, pkgB, pkgC),
			FileMetadata: map[file.Coordinates]file.Metadata{
				coord1: {MIMEType: "text/plain"},
				coord2: {MIMEType: "application/x-sharedlib"},
				coord3: {MIMEType: "text/plain"},
			},
			FileDigests: map[file.Coordinates][]file.Digest{
				coord1: {{Algorithm: "sha256", Value: "abc123"}},
				coord2: {{Algorithm: "sha256", Value: "def456"}},
				coord3: {{Algorithm: "sha256", Value: "ghi789"}},
			},
			LinuxDistribution: &linux.Release{ID: "alpine", VersionID: "3.12"},
		},
		Relationships: []artifact.Relationship{
			// pkgA owns pkgB via file overlap
			{
				From: pkgA,
				To:   pkgB,
				Type: artifact.OwnershipByFileOverlapRelationship,
			},
			// pkgA is evident by coord1
			{
				From: pkgA,
				To:   coord1,
				Type: artifact.EvidentByRelationship,
			},
			// pkgB is evident by coord2
			{
				From: pkgB,
				To:   coord2,
				Type: artifact.EvidentByRelationship,
			},
			// pkgC is evident by coord3 (unrelated)
			{
				From: pkgC,
				To:   coord3,
				Type: artifact.EvidentByRelationship,
			},
		},
		Source: source.Description{
			ID:   "test-source-id",
			Name: "test-image",
		},
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: "test",
		},
	}

	tests := []struct {
		name                   string
		targetPackages         []pkg.Package
		dropLocationFSID       bool
		dropNonPrimaryEvidence bool
		wantCount              int
		verify                 func(t *testing.T, results []Result)
	}{
		{
			name:             "split single package with connected packages",
			targetPackages:   []pkg.Package{pkgA},
			dropLocationFSID: false,
			wantCount:        1,
			verify: func(t *testing.T, results []Result) {
				require.Len(t, results, 1)
				result := results[0]

				// target package should be pkgA
				assert.Equal(t, pkgA.Name, result.TargetPackage.Name)

				// should include both pkgA and pkgB (connected via ownership)
				assert.Equal(t, 2, result.SBOM.Artifacts.Packages.PackageCount())

				// should include coord1 and coord2 (related to pkgA and pkgB)
				assert.Contains(t, result.SBOM.Artifacts.FileMetadata, coord1)
				assert.Contains(t, result.SBOM.Artifacts.FileMetadata, coord2)

				// should NOT include coord3 (unrelated)
				assert.NotContains(t, result.SBOM.Artifacts.FileMetadata, coord3)

				// source and descriptor should be preserved
				assert.Equal(t, "test-source-id", result.SBOM.Source.ID)
				assert.Equal(t, "syft", result.SBOM.Descriptor.Name)

				// linux distribution should be preserved
				require.NotNil(t, result.SBOM.Artifacts.LinuxDistribution)
				assert.Equal(t, "alpine", result.SBOM.Artifacts.LinuxDistribution.ID)
			},
		},
		{
			name:             "split unrelated package",
			targetPackages:   []pkg.Package{pkgC},
			dropLocationFSID: false,
			wantCount:        1,
			verify: func(t *testing.T, results []Result) {
				require.Len(t, results, 1)
				result := results[0]

				// should only include pkgC
				assert.Equal(t, 1, result.SBOM.Artifacts.Packages.PackageCount())

				// should only include coord3
				assert.Contains(t, result.SBOM.Artifacts.FileMetadata, coord3)
				assert.NotContains(t, result.SBOM.Artifacts.FileMetadata, coord1)
				assert.NotContains(t, result.SBOM.Artifacts.FileMetadata, coord2)
			},
		},
		{
			name:             "split with dropLocationFSID",
			targetPackages:   []pkg.Package{pkgA},
			dropLocationFSID: true,
			wantCount:        1,
			verify: func(t *testing.T, results []Result) {
				require.Len(t, results, 1)
				result := results[0]

				// FileSystemID should be cleared from coordinates
				for coord := range result.SBOM.Artifacts.FileMetadata {
					assert.Empty(t, coord.FileSystemID, "FileSystemID should be empty")
				}

				// package locations should also have FileSystemID cleared
				for p := range result.SBOM.Artifacts.Packages.Enumerate() {
					for _, loc := range p.Locations.ToSlice() {
						assert.Empty(t, loc.FileSystemID, "package location FileSystemID should be empty")
					}
				}
			},
		},
		{
			name:             "split multiple packages",
			targetPackages:   []pkg.Package{pkgA, pkgC},
			dropLocationFSID: false,
			wantCount:        2,
			verify: func(t *testing.T, results []Result) {
				require.Len(t, results, 2)

				// first result should be for pkgA
				assert.Equal(t, pkgA.Name, results[0].TargetPackage.Name)

				// second result should be for pkgC
				assert.Equal(t, pkgC.Name, results[1].TargetPackage.Name)
			},
		},
		{
			name:             "empty target packages",
			targetPackages:   []pkg.Package{},
			dropLocationFSID: false,
			wantCount:        0,
			verify: func(t *testing.T, results []Result) {
				assert.Nil(t, results)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := Split(sourceSBOM, tt.targetPackages, tt.dropLocationFSID, tt.dropNonPrimaryEvidence)

			if tt.wantCount == 0 {
				assert.Nil(t, results)
			} else {
				require.Len(t, results, tt.wantCount)
			}

			if tt.verify != nil {
				tt.verify(t, results)
			}
		})
	}
}

func TestFindConnectedPackages(t *testing.T) {
	// create test packages
	pkgA := pkg.Package{Name: "a", Version: "1.0"}
	pkgA.SetID()

	pkgB := pkg.Package{Name: "b", Version: "1.0"}
	pkgB.SetID()

	pkgC := pkg.Package{Name: "c", Version: "1.0"}
	pkgC.SetID()

	pkgD := pkg.Package{Name: "d", Version: "1.0"}
	pkgD.SetID()

	tests := []struct {
		name          string
		target        pkg.Package
		relationships []artifact.Relationship
		wantNames     []string
	}{
		{
			name:   "single package no relationships",
			target: pkgA,
			relationships: []artifact.Relationship{
				// pkgB -> pkgC (unrelated)
				{From: pkgB, To: pkgC, Type: artifact.OwnershipByFileOverlapRelationship},
			},
			wantNames: []string{"a"},
		},
		{
			name:   "connected via ownership-by-file-overlap",
			target: pkgA,
			relationships: []artifact.Relationship{
				{From: pkgA, To: pkgB, Type: artifact.OwnershipByFileOverlapRelationship},
			},
			wantNames: []string{"a", "b"},
		},
		{
			name:   "connected via evident-by (to package)",
			target: pkgA,
			relationships: []artifact.Relationship{
				{From: pkgA, To: pkgB, Type: artifact.EvidentByRelationship},
			},
			wantNames: []string{"a", "b"},
		},
		{
			name:   "chain of connections",
			target: pkgA,
			relationships: []artifact.Relationship{
				{From: pkgA, To: pkgB, Type: artifact.OwnershipByFileOverlapRelationship},
				{From: pkgB, To: pkgC, Type: artifact.OwnershipByFileOverlapRelationship},
			},
			wantNames: []string{"a", "b", "c"},
		},
		{
			name:   "circular relationships",
			target: pkgA,
			relationships: []artifact.Relationship{
				{From: pkgA, To: pkgB, Type: artifact.OwnershipByFileOverlapRelationship},
				{From: pkgB, To: pkgC, Type: artifact.OwnershipByFileOverlapRelationship},
				{From: pkgC, To: pkgA, Type: artifact.OwnershipByFileOverlapRelationship},
			},
			wantNames: []string{"a", "b", "c"},
		},
		{
			name:   "ignores contains relationship",
			target: pkgA,
			relationships: []artifact.Relationship{
				{From: pkgA, To: pkgB, Type: artifact.ContainsRelationship},
			},
			wantNames: []string{"a"},
		},
		{
			name:   "ignores dependency-of relationship",
			target: pkgA,
			relationships: []artifact.Relationship{
				{From: pkgA, To: pkgB, Type: artifact.DependencyOfRelationship},
			},
			wantNames: []string{"a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sourceSBOM := sbom.SBOM{
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(pkgA, pkgB, pkgC, pkgD),
				},
				Relationships: tt.relationships,
			}

			relIndex := newRelationshipIndex(sourceSBOM.Relationships...)
			got := findConnectedPackages(sourceSBOM, tt.target, relIndex)

			gotNames := make([]string, len(got))
			for i, p := range got {
				gotNames[i] = p.Name
			}

			// sort for comparison
			assert.ElementsMatch(t, tt.wantNames, gotNames)
		})
	}
}

func TestClearPackageFileSystemIDs(t *testing.T) {
	coord := file.Coordinates{RealPath: "/test/path", FileSystemID: "layer123"}
	loc := file.NewLocationFromCoordinates(coord)
	loc.AccessPath = "/test/access"

	licLoc := file.NewLocationFromCoordinates(coord)
	lic := pkg.License{
		Value:     "MIT",
		Locations: file.NewLocationSet(licLoc),
	}

	p := pkg.Package{
		Name:      "test",
		Version:   "1.0",
		Locations: file.NewLocationSet(loc),
		Licenses:  pkg.NewLicenseSet(lic),
	}

	result := clearPackageFileSystemIDs(p)

	// check package locations
	for _, l := range result.Locations.ToSlice() {
		assert.Empty(t, l.FileSystemID, "package location FileSystemID should be empty")
		assert.Equal(t, "/test/path", l.RealPath)
		assert.Equal(t, "/test/access", l.AccessPath)
	}

	// check license locations
	for _, l := range result.Licenses.ToSlice() {
		for _, ll := range l.Locations.ToSlice() {
			assert.Empty(t, ll.FileSystemID, "license location FileSystemID should be empty")
		}
	}
}

func TestPackageIDStabilityThroughSplit(t *testing.T) {
	// this test verifies that package IDs remain stable through all split transformations,
	// including dropping licenses, filtering locations, and clearing filesystem IDs.
	// Package IDs are content-addressable and should NOT change when we modify packages
	// during the split process.

	// create a package with multiple locations (primary and non-primary evidence)
	primaryLoc := file.NewLocation("/lib/apk/db/installed")
	primaryLoc.Annotations = map[string]string{"evidence": "primary"}

	nonPrimaryLoc := file.NewLocation("/some/other/path")
	nonPrimaryLoc.Annotations = map[string]string{"evidence": "supporting"}

	// add filesystem IDs to both
	primaryLoc.Coordinates.FileSystemID = "layer123"
	nonPrimaryLoc.Coordinates.FileSystemID = "layer456"

	// create license with location
	licLoc := file.NewLocation("/lib/apk/db/installed")
	licLoc.Coordinates.FileSystemID = "layer123"
	lic := pkg.License{
		Value:     "MIT",
		Locations: file.NewLocationSet(licLoc),
	}

	testPkg := pkg.Package{
		Name:      "test-package",
		Version:   "1.0.0",
		Type:      pkg.ApkPkg,
		Locations: file.NewLocationSet(primaryLoc, nonPrimaryLoc),
		Licenses:  pkg.NewLicenseSet(lic),
	}
	testPkg.SetID()
	originalID := testPkg.ID()

	// verify original ID is set
	require.NotEmpty(t, originalID, "original package ID should be set")

	// create a simple SBOM for the split operation
	sourceSBOM := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(testPkg),
			FileMetadata: map[file.Coordinates]file.Metadata{
				primaryLoc.Coordinates:    {MIMEType: "text/plain"},
				nonPrimaryLoc.Coordinates: {MIMEType: "text/plain"},
			},
		},
		Relationships: []artifact.Relationship{
			{
				From: testPkg,
				To:   primaryLoc.Coordinates,
				Type: artifact.EvidentByRelationship,
			},
		},
		Source: source.Description{
			ID:   "test-source",
			Name: "test",
		},
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: "test",
		},
	}

	tests := []struct {
		name                   string
		dropLocationFSID       bool
		dropNonPrimaryEvidence bool
	}{
		{
			name:                   "no drop options",
			dropLocationFSID:       false,
			dropNonPrimaryEvidence: false,
		},
		{
			name:                   "drop location:fsid only",
			dropLocationFSID:       true,
			dropNonPrimaryEvidence: false,
		},
		{
			name:                   "drop location:non-primary-evidence only",
			dropLocationFSID:       false,
			dropNonPrimaryEvidence: true,
		},
		{
			name:                   "drop both location options",
			dropLocationFSID:       true,
			dropNonPrimaryEvidence: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := Split(sourceSBOM, []pkg.Package{testPkg}, tt.dropLocationFSID, tt.dropNonPrimaryEvidence)
			require.Len(t, results, 1)

			resultSBOM := results[0].SBOM

			// verify there's exactly one package in the result
			require.Equal(t, 1, resultSBOM.Artifacts.Packages.PackageCount())

			// get the package from the result
			var resultPkg *pkg.Package
			for p := range resultSBOM.Artifacts.Packages.Enumerate() {
				resultPkg = &p
				break
			}
			require.NotNil(t, resultPkg)

			// THE CRITICAL ASSERTION: package ID must remain stable
			assert.Equal(t, originalID, resultPkg.ID(),
				"package ID changed after split with dropLocationFSID=%v, dropNonPrimaryEvidence=%v",
				tt.dropLocationFSID, tt.dropNonPrimaryEvidence)

			// verify the target package ID also matches
			assert.Equal(t, originalID, results[0].TargetPackage.ID(),
				"target package ID changed")

			// additional verification: if we dropped non-primary evidence, locations should be filtered
			if tt.dropNonPrimaryEvidence {
				locs := resultPkg.Locations.ToSlice()
				for _, loc := range locs {
					assert.Equal(t, "primary", loc.Annotations["evidence"],
						"non-primary locations should be filtered out")
				}
			}

			// additional verification: if we dropped fsid, it should be empty
			if tt.dropLocationFSID {
				for _, loc := range resultPkg.Locations.ToSlice() {
					assert.Empty(t, loc.FileSystemID, "FileSystemID should be cleared")
				}
			}
		})
	}
}

func TestPackageIDStabilityWithDropOptions(t *testing.T) {
	// this test verifies that package IDs remain stable when using ApplyDropOptions
	// which includes pkg:licenses

	coord := file.Coordinates{RealPath: "/test/path", FileSystemID: "layer123"}
	loc := file.NewLocationFromCoordinates(coord)
	loc.Annotations = map[string]string{"evidence": "primary"}

	lic := pkg.License{
		Value:     "GPL-2.0",
		Locations: file.NewLocationSet(loc),
	}

	testPkg := pkg.Package{
		Name:      "license-test-pkg",
		Version:   "2.0.0",
		Type:      pkg.ApkPkg,
		Locations: file.NewLocationSet(loc),
		Licenses:  pkg.NewLicenseSet(lic),
		Metadata: pkg.ApkDBEntry{
			Package: "license-test-pkg",
			Files: []pkg.ApkFileRecord{
				{Path: "/usr/bin/test"},
			},
		},
	}
	testPkg.SetID()
	originalID := testPkg.ID()

	require.NotEmpty(t, originalID)

	// create SBOM
	testSBOM := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(testPkg),
		},
		Source: source.Description{
			ID:   "test",
			Name: "test",
		},
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: "test",
		},
	}

	tests := []struct {
		name string
		opts []DropOption
	}{
		{
			name: "drop pkg:licenses",
			opts: []DropOption{DropPkgLicenses},
		},
		{
			name: "drop location:fsid via ApplyDropOptions",
			opts: []DropOption{DropLocationFSID},
		},
		{
			name: "drop location:non-primary-evidence via ApplyDropOptions",
			opts: []DropOption{DropLocationNonPrimaryEvidence},
		},
		{
			name: "drop all location and pkg options",
			opts: []DropOption{DropPkgLicenses, DropLocationFSID, DropLocationNonPrimaryEvidence},
		},
		{
			name: "drop pkg:metadata.files",
			opts: []DropOption{DropPkgMetadataFiles},
		},
		{
			name: "drop all pkg options",
			opts: []DropOption{DropPkgLicenses, DropPkgMetadataFiles},
		},
		{
			name: "drop source and descriptor (should not affect package ID)",
			opts: []DropOption{DropSource, DropDescriptor, DropDistro},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// make a copy of the SBOM for this test
			sbomCopy := sbom.SBOM{
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(testPkg),
				},
				Source:     testSBOM.Source,
				Descriptor: testSBOM.Descriptor,
			}

			// apply drop options
			ApplyDropOptions(&sbomCopy, tt.opts)

			// get the package from the modified SBOM
			var resultPkg *pkg.Package
			for p := range sbomCopy.Artifacts.Packages.Enumerate() {
				resultPkg = &p
				break
			}
			require.NotNil(t, resultPkg)

			// THE CRITICAL ASSERTION: package ID must remain stable
			assert.Equal(t, originalID, resultPkg.ID(),
				"package ID changed after applying drop options: %v", tt.opts)
		})
	}
}
