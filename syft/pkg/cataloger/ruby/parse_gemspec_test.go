package ruby

import (
	"testing"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
)

func TestParseGemspec(t *testing.T) {
	fixture := "test-fixtures/bundler.gemspec"

	locations := source.NewLocationSet(source.NewLocation(fixture))

	var expectedPkg = pkg.Package{
		Name:         "bundler",
		Version:      "2.1.4",
		PURL:         "pkg:gem/bundler@2.1.4",
		Locations:    locations,
		Type:         pkg.GemPkg,
		Licenses:     internal.LogicalStrings{Simple: []string{"MIT"}},
		Language:     pkg.Ruby,
		MetadataType: pkg.GemMetadataType,
		Metadata: pkg.GemMetadata{
			Name:     "bundler",
			Version:  "2.1.4",
			Files:    []string{"exe/bundle", "exe/bundler"},
			Authors:  []string{"André Arko", "Samuel Giddins", "Colby Swandale", "Hiroshi Shibata", "David Rodríguez", "Grey Baker", "Stephanie Morillo", "Chris Morris", "James Wen", "Tim Moore", "André Medeiros", "Jessica Lynn Suttles", "Terence Lee", "Carl Lerche", "Yehuda Katz"},
			Licenses: []string{"MIT"},
			Homepage: "https://bundler.io",
		},
	}

	pkgtest.TestFileParser(t, fixture, parseGemSpecEntries, []pkg.Package{expectedPkg}, nil)
}
