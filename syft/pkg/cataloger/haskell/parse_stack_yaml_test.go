package haskell

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseStackYaml(t *testing.T) {
	fixture := "test-fixtures/stack.yaml"
	locationSet := file.NewLocationSet(file.NewLocation(fixture))

	expectedPkgs := []pkg.Package{
		{
			Name:      "ShellCheck",
			Version:   "0.8.0",
			PURL:      "pkg:hackage/ShellCheck@0.8.0",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
			Metadata: pkg.HackageStackYamlEntry{
				PkgHash: "353c9322847b661e4c6f7c83c2acf8e5c08b682fbe516c7d46c29605937543df",
			},
		},
		{
			Name:      "colourista",
			Version:   "0.1.0.1",
			PURL:      "pkg:hackage/colourista@0.1.0.1",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
			Metadata: pkg.HackageStackYamlEntry{
				PkgHash: "98353ee0e2f5d97d2148513f084c1cd37dfda03e48aa9dd7a017c9d9c0ba710e",
			},
		},
		{
			Name:      "language-docker",
			Version:   "11.0.0",
			PURL:      "pkg:hackage/language-docker@11.0.0",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
			Metadata: pkg.HackageStackYamlEntry{
				PkgHash: "3406ff0c1d592490f53ead8cf2cd22bdf3d79fd125ccaf3add683f6d71c24d55",
			},
		},
		{
			Name:      "spdx",
			Version:   "1.0.0.2",
			PURL:      "pkg:hackage/spdx@1.0.0.2",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
			Metadata: pkg.HackageStackYamlEntry{
				PkgHash: "7dfac9b454ff2da0abb7560f0ffbe00ae442dd5cb76e8be469f77e6988a70fed",
			},
		},
		{
			Name:      "hspec",
			Version:   "2.9.4",
			PURL:      "pkg:hackage/hspec@2.9.4",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
			Metadata: pkg.HackageStackYamlEntry{
				PkgHash: "658a6a74d5a70c040edd6df2a12228c6d9e63082adaad1ed4d0438ad082a0ef3",
			},
		},
		{
			Name:      "hspec-core",
			Version:   "2.9.4",
			PURL:      "pkg:hackage/hspec-core@2.9.4",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
			Metadata: pkg.HackageStackYamlEntry{
				PkgHash: "a126e9087409fef8dcafcd2f8656456527ac7bb163ed4d9cb3a57589042a5fe8",
			},
		},
		{
			Name:      "hspec-discover",
			Version:   "2.9.4",
			PURL:      "pkg:hackage/hspec-discover@2.9.4",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
			Metadata: pkg.HackageStackYamlEntry{
				PkgHash: "fbcf49ecfc3d4da53e797fd0275264cba776ffa324ee223e2a3f4ec2d2c9c4a6",
			},
		},
		{
			Name:      "stm",
			Version:   "2.5.0.2",
			PURL:      "pkg:hackage/stm@2.5.0.2",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
			Metadata: pkg.HackageStackYamlEntry{
				PkgHash: "e4dc6473faaa75fbd7eccab4e3ee1d651d75bb0e49946ef0b8b751ccde771a55",
			},
		},
	}

	// TODO: relationships are not under test yet
	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parseStackYaml, expectedPkgs, expectedRelationships)

}

func Test_corruptStackYaml(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/corrupt/stack.yaml").
		WithError().
		TestParser(t, parseStackYaml)
}
