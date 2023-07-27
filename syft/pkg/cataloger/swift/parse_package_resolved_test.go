package swift

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParsePackageResolved(t *testing.T) {
	fixture := "test-fixtures/Package.resolved"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	expectedPkgs := []pkg.Package{
		{
			Name:         "swift-algorithms",
			Version:      "1.0.0",
			PURL:         "pkg:swift/github.com/apple/swift-algorithms.git/swift-algorithms@1.0.0",
			Locations:    locations,
			Language:     pkg.Swift,
			Type:         pkg.SwiftPkg,
			MetadataType: pkg.SwiftPackageManagerMetadataType,
			Metadata: pkg.SwiftPackageManagerMetadata{
				Revision: "b14b7f4c528c942f121c8b860b9410b2bf57825e",
			},
		},
		{
			Name:         "swift-async-algorithms",
			Version:      "0.1.0",
			PURL:         "pkg:swift/github.com/apple/swift-async-algorithms.git/swift-async-algorithms@0.1.0",
			Locations:    locations,
			Language:     pkg.Swift,
			Type:         pkg.SwiftPkg,
			MetadataType: pkg.SwiftPackageManagerMetadataType,
			Metadata: pkg.SwiftPackageManagerMetadata{
				Revision: "9cfed92b026c524674ed869a4ff2dcfdeedf8a2a",
			},
		},
		{
			Name:         "swift-atomics",
			Version:      "1.1.0",
			PURL:         "pkg:swift/github.com/apple/swift-atomics.git/swift-atomics@1.1.0",
			Locations:    locations,
			Language:     pkg.Swift,
			Type:         pkg.SwiftPkg,
			MetadataType: pkg.SwiftPackageManagerMetadataType,
			Metadata: pkg.SwiftPackageManagerMetadata{
				Revision: "6c89474e62719ddcc1e9614989fff2f68208fe10",
			},
		},
		{
			Name:         "swift-collections",
			Version:      "1.0.4",
			PURL:         "pkg:swift/github.com/apple/swift-collections.git/swift-collections@1.0.4",
			Locations:    locations,
			Language:     pkg.Swift,
			Type:         pkg.SwiftPkg,
			MetadataType: pkg.SwiftPackageManagerMetadataType,
			Metadata: pkg.SwiftPackageManagerMetadata{
				Revision: "937e904258d22af6e447a0b72c0bc67583ef64a2",
			},
		},
		{
			Name:         "swift-numerics",
			Version:      "1.0.2",
			PURL:         "pkg:swift/github.com/apple/swift-numerics/swift-numerics@1.0.2",
			Locations:    locations,
			Language:     pkg.Swift,
			Type:         pkg.SwiftPkg,
			MetadataType: pkg.SwiftPackageManagerMetadataType,
			Metadata: pkg.SwiftPackageManagerMetadata{
				Revision: "0a5bc04095a675662cf24757cc0640aa2204253b",
			},
		},
	}

	// TODO: no relationships are under test yet
	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parsePackageResolved, expectedPkgs, expectedRelationships)
}
