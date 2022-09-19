package haskell

import (
	"os"
	"testing"

	"github.com/go-test/deep"

	"github.com/anchore/syft/syft/pkg"
)

func fixtureP(str string) *string {
	return &str
}

func TestParseStackLock(t *testing.T) {
	url := "https://raw.githubusercontent.com/commercialhaskell/stackage-snapshots/master/lts/19/14.yaml"
	expected := []*pkg.Package{
		{
			Name:         "HTTP",
			Version:      "4000.3.16",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:        "HTTP",
				Version:     "4000.3.16",
				PkgHash:     fixtureP("6042643c15a0b43e522a6693f1e322f05000d519543a84149cb80aeffee34f71"),
				SnapshotURL: &url,
			},
		},
		{
			Name:         "configurator-pg",
			Version:      "0.2.6",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:        "configurator-pg",
				Version:     "0.2.6",
				PkgHash:     fixtureP("cd9b06a458428e493a4d6def725af7ab1ab0fef678fbd871f9586fc7f9aa70be"),
				SnapshotURL: &url,
			},
		},
		{
			Name:         "hasql-dynamic-statements",
			Version:      "0.3.1.1",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:        "hasql-dynamic-statements",
				Version:     "0.3.1.1",
				PkgHash:     fixtureP("2cfe6e75990e690f595a87cbe553f2e90fcd738610f6c66749c81cc4396b2cc4"),
				SnapshotURL: &url,
			},
		},
		{
			Name:         "hasql-implicits",
			Version:      "0.1.0.4",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:        "hasql-implicits",
				Version:     "0.1.0.4",
				PkgHash:     fixtureP("0848d3cbc9d94e1e539948fa0be4d0326b26335034161bf8076785293444ca6f"),
				SnapshotURL: &url,
			},
		},
		{
			Name:         "hasql-pool",
			Version:      "0.5.2.2",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:        "hasql-pool",
				Version:     "0.5.2.2",
				PkgHash:     fixtureP("b56d4dea112d97a2ef4b2749508c0ca646828cb2d77b827e8dc433d249bb2062"),
				SnapshotURL: &url,
			},
		},
		{
			Name:         "lens-aeson",
			Version:      "1.1.3",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:        "lens-aeson",
				Version:     "1.1.3",
				PkgHash:     fixtureP("52c8eaecd2d1c2a969c0762277c4a8ee72c339a686727d5785932e72ef9c3050"),
				SnapshotURL: &url,
			},
		},
		{
			Name:         "optparse-applicative",
			Version:      "0.16.1.0",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:        "optparse-applicative",
				Version:     "0.16.1.0",
				PkgHash:     fixtureP("418c22ed6a19124d457d96bc66bd22c93ac22fad0c7100fe4972bbb4ac989731"),
				SnapshotURL: &url,
			},
		},
		{
			Name:         "protolude",
			Version:      "0.3.2",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:        "protolude",
				Version:     "0.3.2",
				PkgHash:     fixtureP("2a38b3dad40d238ab644e234b692c8911423f9d3ed0e36b62287c4a698d92cd1"),
				SnapshotURL: &url,
			},
		},
		{
			Name:         "ptr",
			Version:      "0.16.8.2",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:        "ptr",
				Version:     "0.16.8.2",
				PkgHash:     fixtureP("708ebb95117f2872d2c5a554eb6804cf1126e86abe793b2673f913f14e5eb1ac"),
				SnapshotURL: &url,
			},
		},
	}

	fixture, err := os.Open("test-fixtures/stack.yaml.lock")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	// TODO: no relationships are under test yet
	actual, _, err := parseStackLock(fixture.Name(), fixture)
	if err != nil {
		t.Error(err)
	}

	differences := deep.Equal(expected, actual)
	if differences != nil {
		t.Errorf("returned package list differed from expectation: %+v", differences)
	}
}
