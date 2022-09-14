package haskell

import (
	"os"
	"testing"

	"github.com/go-test/deep"

	"github.com/anchore/syft/syft/pkg"
)

func TestParseCabalFreeze(t *testing.T) {
	expected := []*pkg.Package{
		{
			Name:         "Cabal",
			Version:      "3.2.1.0",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:    "Cabal",
				Version: "3.2.1.0",
			},
		},
		{
			Name:         "Diff",
			Version:      "0.4.1",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:    "Diff",
				Version: "0.4.1",
			},
		},
		{
			Name:         "HTTP",
			Version:      "4000.3.16",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:    "HTTP",
				Version: "4000.3.16",
			},
		},
		{
			Name:         "HUnit",
			Version:      "1.6.2.0",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:    "HUnit",
				Version: "1.6.2.0",
			},
		},
		{
			Name:         "OneTuple",
			Version:      "0.3.1",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:    "OneTuple",
				Version: "0.3.1",
			},
		},
		{
			Name:         "Only",
			Version:      "0.1",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:    "Only",
				Version: "0.1",
			},
		},
		{
			Name:         "PyF",
			Version:      "0.10.2.0",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:    "PyF",
				Version: "0.10.2.0",
			},
		},
		{
			Name:         "QuickCheck",
			Version:      "2.14.2",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:    "QuickCheck",
				Version: "2.14.2",
			},
		},
		{
			Name:         "RSA",
			Version:      "2.4.1",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:    "RSA",
				Version: "2.4.1",
			},
		},
		{
			Name:         "SHA",
			Version:      "1.6.4.4",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:    "SHA",
				Version: "1.6.4.4",
			},
		},
		{
			Name:         "Spock",
			Version:      "0.14.0.0",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:    "Spock",
				Version: "0.14.0.0",
			},
		},
	}

	fixture, err := os.Open("test-fixtures/cabal.project.freeze")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	// TODO: no relationships are under test yet
	actual, _, err := parseCabalFreeze(fixture.Name(), fixture)
	if err != nil {
		t.Error(err)
	}

	differences := deep.Equal(expected, actual)
	if differences != nil {
		t.Errorf("returned package list differed from expectation: %+v", differences)
	}
}
