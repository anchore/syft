package swipl

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParsePackPackage(t *testing.T) {
	fixture := "test-fixtures/pack.pl"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	expectedPkgs := []pkg.Package{
		{
			Name:      "hdt",
			Version:   "0.5.2",
			PURL:      "pkg:swiplpack/hdt@0.5.2",
			Locations: locations,
			Language:  pkg.Swipl,
			Type:      pkg.SwiplPackPkg,
			Metadata: pkg.SwiplPackEntry{
				Name:          "hdt",
				Version:       "0.5.2",
				Author:        "Jan Wielemaker",
				AuthorEmail:   "J.Wielemaker@vu.nl",
				Packager:      "Jan Wielemaker",
				PackagerEmail: "J.Wielemaker@vu.nl",
				Homepage:      "https://github.com/JanWielemaker/hdt",
			},
		},
	}

	// TODO: no relationships are under test yet
	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parsePackPackage, expectedPkgs, expectedRelationships)
}
