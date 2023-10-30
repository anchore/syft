package ruby

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseGemspec(t *testing.T) {
	fixture := "test-fixtures/bundler.gemspec"

	locations := file.NewLocationSet(file.NewLocation(fixture))

	var expectedPkg = pkg.Package{
		Name:      "bundler",
		Version:   "2.1.4",
		PURL:      "pkg:gem/bundler@2.1.4",
		Locations: locations,
		Type:      pkg.GemPkg,
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseFromLocations("MIT", file.NewLocation(fixture)),
		),
		Language: pkg.Ruby,
		Metadata: pkg.RubyGemspec{
			Name:     "bundler",
			Version:  "2.1.4",
			Files:    []string{"exe/bundle", "exe/bundler"},
			Authors:  []string{"André Arko", "Samuel Giddins", "Colby Swandale", "Hiroshi Shibata", "David Rodríguez", "Grey Baker", "Stephanie Morillo", "Chris Morris", "James Wen", "Tim Moore", "André Medeiros", "Jessica Lynn Suttles", "Terence Lee", "Carl Lerche", "Yehuda Katz"},
			Homepage: "https://bundler.io",
		},
	}

	pkgtest.TestFileParser(t, fixture, parseGemSpecEntries, []pkg.Package{expectedPkg}, nil)
}
