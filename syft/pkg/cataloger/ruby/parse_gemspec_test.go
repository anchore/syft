package ruby

import (
	"context"
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseGemspec(t *testing.T) {
	fixture := "testdata/bundler.gemspec"
	ctx := context.TODO()
	locations := file.NewLocationSet(file.NewLocation(fixture))

	var expectedPkg = pkg.Package{
		Name:      "bundler",
		Version:   "2.1.4",
		PURL:      "pkg:gem/bundler@2.1.4",
		Locations: locations,
		Type:      pkg.GemPkg,
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseFromLocationsWithContext(ctx, "MIT", file.NewLocation(fixture)),
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

// Regression test for https://github.com/anchore/syft/issues/4720:
// gemspecs routinely build URL fields from Ruby string interpolation
// (e.g. "https://github.com/geemus/#{s.name}"), and syft used to pass
// those interpolations through into the emitted SBOM, producing URLs
// containing `{` and `}` that fail CycloneDX IRI validation.
func TestParseGemspec_ResolvesRubyInterpolation(t *testing.T) {
	fixture := "testdata/formatador.gemspec"
	ctx := context.TODO()
	locations := file.NewLocationSet(file.NewLocation(fixture))

	expectedPkg := pkg.Package{
		Name:      "formatador",
		Version:   "1.1.0",
		PURL:      "pkg:gem/formatador@1.1.0",
		Locations: locations,
		Type:      pkg.GemPkg,
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseFromLocationsWithContext(ctx, "MIT", file.NewLocation(fixture)),
		),
		Language: pkg.Ruby,
		Metadata: pkg.RubyGemspec{
			Name:    "formatador",
			Version: "1.1.0",
			Files:   []string{"lib/formatador.rb"},
			Authors: []string{"geemus (Wesley Beary)"},
			// #{s.name} should have been resolved to the captured name.
			Homepage: "https://github.com/geemus/formatador",
		},
	}

	pkgtest.TestFileParser(t, fixture, parseGemSpecEntries, []pkg.Package{expectedPkg}, nil)
}
