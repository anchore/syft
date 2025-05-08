package swift

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

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
			Name:      "swift-algorithms",
			Version:   "1.0.0",
			PURL:      "pkg:swift/github.com/apple/swift-algorithms.git/swift-algorithms@1.0.0",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.SwiftPkg,
			Metadata: pkg.SwiftPackageManagerResolvedEntry{
				Revision: "b14b7f4c528c942f121c8b860b9410b2bf57825e",
			},
		},
		{
			Name:      "swift-async-algorithms",
			Version:   "0.1.0",
			PURL:      "pkg:swift/github.com/apple/swift-async-algorithms.git/swift-async-algorithms@0.1.0",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.SwiftPkg,
			Metadata: pkg.SwiftPackageManagerResolvedEntry{
				Revision: "9cfed92b026c524674ed869a4ff2dcfdeedf8a2a",
			},
		},
		{
			Name:      "swift-atomics",
			Version:   "1.1.0",
			PURL:      "pkg:swift/github.com/apple/swift-atomics.git/swift-atomics@1.1.0",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.SwiftPkg,
			Metadata: pkg.SwiftPackageManagerResolvedEntry{
				Revision: "6c89474e62719ddcc1e9614989fff2f68208fe10",
			},
		},
		{
			Name:      "swift-collections",
			Version:   "1.0.4",
			PURL:      "pkg:swift/github.com/apple/swift-collections.git/swift-collections@1.0.4",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.SwiftPkg,
			Metadata: pkg.SwiftPackageManagerResolvedEntry{
				Revision: "937e904258d22af6e447a0b72c0bc67583ef64a2",
			},
		},
		{
			Name:      "swift-numerics",
			Version:   "1.0.2",
			PURL:      "pkg:swift/github.com/apple/swift-numerics/swift-numerics@1.0.2",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.SwiftPkg,
			Metadata: pkg.SwiftPackageManagerResolvedEntry{
				Revision: "0a5bc04095a675662cf24757cc0640aa2204253b",
			},
		},
	}

	// TODO: no relationships are under test yet
	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parsePackageResolved, expectedPkgs, expectedRelationships)
}

func TestParsePackageResolvedV3(t *testing.T) {
	fixture := "test-fixtures/PackageV3.resolved"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	expectedPkgs := []pkg.Package{
		{
			Name:      "swift-mmio",
			Version:   "",
			PURL:      "pkg:swift/github.com/apple/swift-mmio/swift-mmio",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.SwiftPkg,
			Metadata: pkg.SwiftPackageManagerResolvedEntry{
				Revision: "80c109b87511041338a4d8d88064088c8dfc079b",
			},
		},
		{
			Name:      "swift-syntax",
			Version:   "509.1.1",
			PURL:      "pkg:swift/github.com/apple/swift-syntax.git/swift-syntax@509.1.1",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.SwiftPkg,
			Metadata: pkg.SwiftPackageManagerResolvedEntry{
				Revision: "64889f0c732f210a935a0ad7cda38f77f876262d",
			},
		},
	}

	// TODO: no relationships are under test yet
	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parsePackageResolved, expectedPkgs, expectedRelationships)
}

func TestParsePackageResolved_empty(t *testing.T) {
	// regression for https://github.com/anchore/syft/issues/2225
	fixture := "test-fixtures/empty-packages.resolved"

	pkgtest.TestFileParser(t, fixture, parsePackageResolved, nil, nil)

	dir := t.TempDir()
	fixture = filepath.Join(dir, "Package.resolved")
	_, err := os.Create(fixture)
	require.NoError(t, err)

	pkgtest.TestFileParser(t, fixture, parsePackageResolved, nil, nil)
}

func TestParsePackageResolved_versionNotANumber(t *testing.T) {
	// regression for https://github.com/anchore/syft/issues/2225
	fixture := "test-fixtures/bad-version-packages.resolved"

	pkgtest.NewCatalogTester().FromFile(t, fixture).WithError().TestParser(t, parsePackageResolved)
}

func Test_corruptPackageResolved(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/bad-version-packages.resolved").
		WithError().
		TestParser(t, parsePackageResolved)
}
