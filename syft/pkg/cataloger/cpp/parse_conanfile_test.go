package cpp

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseConanfile(t *testing.T) {
	fixture := "test-fixtures/conanfile.txt"
	fixtureLocationSet := file.NewLocationSet(file.NewLocation(fixture))
	expected := []pkg.Package{
		{
			Name:      "catch2",
			Version:   "2.13.8",
			PURL:      "pkg:conan/catch2@2.13.8",
			Locations: fixtureLocationSet,
			Language:  pkg.CPP,
			Type:      pkg.ConanPkg,
			Metadata: pkg.ConanfileEntry{
				Ref: "catch2/2.13.8",
			},
		},
		{
			Name:      "docopt.cpp",
			Version:   "0.6.3",
			PURL:      "pkg:conan/docopt.cpp@0.6.3",
			Locations: fixtureLocationSet,
			Language:  pkg.CPP,
			Type:      pkg.ConanPkg,
			Metadata: pkg.ConanfileEntry{
				Ref: "docopt.cpp/0.6.3",
			},
		},
		{
			Name:      "fmt",
			Version:   "8.1.1",
			PURL:      "pkg:conan/fmt@8.1.1",
			Locations: fixtureLocationSet,
			Language:  pkg.CPP,
			Type:      pkg.ConanPkg,
			Metadata: pkg.ConanfileEntry{
				Ref: "fmt/8.1.1",
			},
		},
		{
			Name:      "spdlog",
			Version:   "1.9.2",
			PURL:      "pkg:conan/my_user/spdlog@1.9.2?channel=my_channel",
			Locations: fixtureLocationSet,
			Language:  pkg.CPP,
			Type:      pkg.ConanPkg,
			Metadata: pkg.ConanfileEntry{
				Ref: "spdlog/1.9.2@my_user/my_channel#1234567%%987654",
			},
		},
		{
			Name:      "sdl",
			Version:   "2.0.20",
			PURL:      "pkg:conan/sdl@2.0.20",
			Locations: fixtureLocationSet,
			Language:  pkg.CPP,
			Type:      pkg.ConanPkg,
			Metadata: pkg.ConanfileEntry{
				Ref: "sdl/2.0.20#1234567%%987654",
			},
		},
		{
			Name:      "fltk",
			Version:   "1.3.8",
			PURL:      "pkg:conan/my_user/fltk@1.3.8?channel=my_channel",
			Locations: fixtureLocationSet,
			Language:  pkg.CPP,
			Type:      pkg.ConanPkg,
			Metadata: pkg.ConanfileEntry{
				Ref: "fltk/1.3.8@my_user/my_channel",
			},
		},
	}

	// TODO: relationships are not under test
	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parseConanfile, expected, expectedRelationships)
}
