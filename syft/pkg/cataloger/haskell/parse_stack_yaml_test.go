package haskell

import (
	"os"
	"testing"

	"github.com/go-test/deep"

	"github.com/anchore/syft/syft/pkg"
)

func TestParseStackYaml(t *testing.T) {
	expected := []*pkg.Package{
		{
			Name:         "ShellCheck",
			Version:      "0.8.0",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:    "ShellCheck",
				Version: "0.8.0",
				PkgHash: fixtureP("353c9322847b661e4c6f7c83c2acf8e5c08b682fbe516c7d46c29605937543df"),
			},
		},
		{
			Name:         "colourista",
			Version:      "0.1.0.1",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:    "colourista",
				Version: "0.1.0.1",
				PkgHash: fixtureP("98353ee0e2f5d97d2148513f084c1cd37dfda03e48aa9dd7a017c9d9c0ba710e"),
			},
		},
		{
			Name:         "language-docker",
			Version:      "11.0.0",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:    "language-docker",
				Version: "11.0.0",
				PkgHash: fixtureP("3406ff0c1d592490f53ead8cf2cd22bdf3d79fd125ccaf3add683f6d71c24d55"),
			},
		},
		{
			Name:         "spdx",
			Version:      "1.0.0.2",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:    "spdx",
				Version: "1.0.0.2",
				PkgHash: fixtureP("7dfac9b454ff2da0abb7560f0ffbe00ae442dd5cb76e8be469f77e6988a70fed"),
			},
		},
		{
			Name:         "hspec",
			Version:      "2.9.4",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:    "hspec",
				Version: "2.9.4",
				PkgHash: fixtureP("658a6a74d5a70c040edd6df2a12228c6d9e63082adaad1ed4d0438ad082a0ef3"),
			},
		},
		{
			Name:         "hspec-core",
			Version:      "2.9.4",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:    "hspec-core",
				Version: "2.9.4",
				PkgHash: fixtureP("a126e9087409fef8dcafcd2f8656456527ac7bb163ed4d9cb3a57589042a5fe8"),
			},
		},
		{
			Name:         "hspec-discover",
			Version:      "2.9.4",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:    "hspec-discover",
				Version: "2.9.4",
				PkgHash: fixtureP("fbcf49ecfc3d4da53e797fd0275264cba776ffa324ee223e2a3f4ec2d2c9c4a6"),
			},
		},
		{
			Name:         "stm",
			Version:      "2.5.0.2",
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:    "stm",
				Version: "2.5.0.2",
				PkgHash: fixtureP("e4dc6473faaa75fbd7eccab4e3ee1d651d75bb0e49946ef0b8b751ccde771a55"),
			},
		},
	}

	fixture, err := os.Open("test-fixtures/stack.yaml")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	// TODO: no relationships are under test yet
	actual, _, err := parseStackYaml(fixture.Name(), fixture)
	if err != nil {
		t.Error(err)
	}

	differences := deep.Equal(expected, actual)
	if differences != nil {
		t.Errorf("returned package list differed from expectation: %+v", differences)
	}
}
