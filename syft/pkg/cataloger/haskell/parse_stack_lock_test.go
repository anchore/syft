package haskell

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseStackLock(t *testing.T) {
	url := "https://raw.githubusercontent.com/commercialhaskell/stackage-snapshots/master/lts/19/14.yaml"
	fixture := "test-fixtures/stack.yaml.lock"
	locationSet := file.NewLocationSet(file.NewLocation(fixture))

	expectedPkgs := []pkg.Package{
		{
			Name:      "HTTP",
			Version:   "4000.3.16",
			PURL:      "pkg:hackage/HTTP@4000.3.16",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
			Metadata: pkg.HackageStackYamlLockEntry{
				PkgHash:     "6042643c15a0b43e522a6693f1e322f05000d519543a84149cb80aeffee34f71",
				SnapshotURL: url,
			},
		},
		{
			Name:      "configurator-pg",
			Version:   "0.2.6",
			PURL:      "pkg:hackage/configurator-pg@0.2.6",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
			Metadata: pkg.HackageStackYamlLockEntry{
				PkgHash:     "cd9b06a458428e493a4d6def725af7ab1ab0fef678fbd871f9586fc7f9aa70be",
				SnapshotURL: url,
			},
		},
		{
			Name:      "hasql-dynamic-statements",
			Version:   "0.3.1.1",
			PURL:      "pkg:hackage/hasql-dynamic-statements@0.3.1.1",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
			Metadata: pkg.HackageStackYamlLockEntry{
				PkgHash:     "2cfe6e75990e690f595a87cbe553f2e90fcd738610f6c66749c81cc4396b2cc4",
				SnapshotURL: url,
			},
		},
		{
			Name:      "hasql-implicits",
			Version:   "0.1.0.4",
			PURL:      "pkg:hackage/hasql-implicits@0.1.0.4",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
			Metadata: pkg.HackageStackYamlLockEntry{
				PkgHash:     "0848d3cbc9d94e1e539948fa0be4d0326b26335034161bf8076785293444ca6f",
				SnapshotURL: url,
			},
		},
		{
			Name:      "hasql-pool",
			Version:   "0.5.2.2",
			PURL:      "pkg:hackage/hasql-pool@0.5.2.2",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
			Metadata: pkg.HackageStackYamlLockEntry{
				PkgHash:     "b56d4dea112d97a2ef4b2749508c0ca646828cb2d77b827e8dc433d249bb2062",
				SnapshotURL: url,
			},
		},
		{
			Name:      "lens-aeson",
			Version:   "1.1.3",
			PURL:      "pkg:hackage/lens-aeson@1.1.3",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
			Metadata: pkg.HackageStackYamlLockEntry{
				PkgHash:     "52c8eaecd2d1c2a969c0762277c4a8ee72c339a686727d5785932e72ef9c3050",
				SnapshotURL: url,
			},
		},
		{
			Name:      "optparse-applicative",
			Version:   "0.16.1.0",
			PURL:      "pkg:hackage/optparse-applicative@0.16.1.0",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
			Metadata: pkg.HackageStackYamlLockEntry{
				PkgHash:     "418c22ed6a19124d457d96bc66bd22c93ac22fad0c7100fe4972bbb4ac989731",
				SnapshotURL: url,
			},
		},
		{
			Name:      "protolude",
			Version:   "0.3.2",
			PURL:      "pkg:hackage/protolude@0.3.2",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
			Metadata: pkg.HackageStackYamlLockEntry{
				PkgHash:     "2a38b3dad40d238ab644e234b692c8911423f9d3ed0e36b62287c4a698d92cd1",
				SnapshotURL: url,
			},
		},
		{
			Name:      "ptr",
			Version:   "0.16.8.2",
			PURL:      "pkg:hackage/ptr@0.16.8.2",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
			Metadata: pkg.HackageStackYamlLockEntry{
				PkgHash:     "708ebb95117f2872d2c5a554eb6804cf1126e86abe793b2673f913f14e5eb1ac",
				SnapshotURL: url,
			},
		},
	}

	// TODO: relationships are not under test yet
	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parseStackLock, expectedPkgs, expectedRelationships)
}

func Test_corruptStackLock(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/corrupt/stack.yaml.lock").
		WithError().
		TestParser(t, parseStackLock)
}
