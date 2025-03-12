package homebrew

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseHomebrewPackage(t *testing.T) {
	var expectedRelationships []artifact.Relationship

	fixture := "test-fixtures/glob-paths/Cellar/foo/1.2.3/.brew/foo.rb"
	fixtureLocation := file.NewLocation(fixture)
	locations := file.NewLocationSet(fixtureLocation)

	cellarPath := "test-fixtures/glob-paths/Cellar/foo/1.2.3"
	locations.Add(file.NewLocation(cellarPath))

	expected := pkg.Package{
		Name:      "foo",
		Version:   "1.2.3",
		Type:      pkg.HomebrewPkg,
		Language:  pkg.Ruby,
		Locations: locations,
		FoundBy:   "homebrew-cataloger",
		PURL:      "pkg:homebrew/foo@1.2.3",
		Metadata: pkg.HomebrewMetadata{
			Name:        "foo",
			FullName:    "foo",
			Tap:         "homebrew/core",
			Homepage:    "https://example.com/foo",
			Description: "A test Homebrew formula for Foo",
		},
	}
	expected.SetID()

	pkgtest.TestFileParser(t, fixture, parseHomebrewPackage, []pkg.Package{expected}, expectedRelationships)
}
