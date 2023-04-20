package haskell

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseCabalFreeze(t *testing.T) {
	fixture := "test-fixtures/cabal.project.freeze"
	locationSet := file.NewLocationSet(file.NewLocation(fixture))

	expectedPkgs := []pkg.Package{
		{
			Name:      "Cabal",
			Version:   "3.2.1.0",
			PURL:      "pkg:hackage/Cabal@3.2.1.0",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
		},
		{
			Name:      "Diff",
			Version:   "0.4.1",
			PURL:      "pkg:hackage/Diff@0.4.1",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
		},
		{
			Name:      "HTTP",
			Version:   "4000.3.16",
			PURL:      "pkg:hackage/HTTP@4000.3.16",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
		},
		{
			Name:      "HUnit",
			Version:   "1.6.2.0",
			PURL:      "pkg:hackage/HUnit@1.6.2.0",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
		},
		{
			Name:      "OneTuple",
			Version:   "0.3.1",
			PURL:      "pkg:hackage/OneTuple@0.3.1",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
		},
		{
			Name:      "Only",
			Version:   "0.1",
			PURL:      "pkg:hackage/Only@0.1",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
		},
		{
			Name:      "PyF",
			Version:   "0.10.2.0",
			PURL:      "pkg:hackage/PyF@0.10.2.0",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
		},
		{
			Name:      "QuickCheck",
			Version:   "2.14.2",
			PURL:      "pkg:hackage/QuickCheck@2.14.2",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
		},
		{
			Name:      "RSA",
			Version:   "2.4.1",
			PURL:      "pkg:hackage/RSA@2.4.1",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
		},
		{
			Name:      "SHA",
			Version:   "1.6.4.4",
			PURL:      "pkg:hackage/SHA@1.6.4.4",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
		},
		{
			Name:      "Spock",
			Version:   "0.14.0.0",
			PURL:      "pkg:hackage/Spock@0.14.0.0",
			Locations: locationSet,
			Language:  pkg.Haskell,
			Type:      pkg.HackagePkg,
		},
	}

	// TODO: relationships are not under test yet
	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parseCabalFreeze, expectedPkgs, expectedRelationships)
}
