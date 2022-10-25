package cpp

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
)

func TestParseConanfile(t *testing.T) {
	fixture := "test-fixtures/conanfile.txt"
	fixtureLocationSet := source.NewLocationSet(source.NewLocation(fixture))
	expected := []pkg.Package{
		{
			Name:         "catch2",
			Version:      "2.13.8",
			PURL:         "pkg:conan/catch2@2.13.8",
			Locations:    fixtureLocationSet,
			Language:     pkg.CPP,
			Type:         pkg.ConanPkg,
			MetadataType: pkg.ConanMetadataType,
			Metadata: pkg.ConanMetadata{
				Ref: "catch2/2.13.8",
			},
		},
		{
			Name:         "docopt.cpp",
			Version:      "0.6.3",
			PURL:         "pkg:conan/docopt.cpp@0.6.3",
			Locations:    fixtureLocationSet,
			Language:     pkg.CPP,
			Type:         pkg.ConanPkg,
			MetadataType: pkg.ConanMetadataType,
			Metadata: pkg.ConanMetadata{
				Ref: "docopt.cpp/0.6.3",
			},
		},
		{
			Name:         "fmt",
			Version:      "8.1.1",
			PURL:         "pkg:conan/fmt@8.1.1",
			Locations:    fixtureLocationSet,
			Language:     pkg.CPP,
			Type:         pkg.ConanPkg,
			MetadataType: pkg.ConanMetadataType,
			Metadata: pkg.ConanMetadata{
				Ref: "fmt/8.1.1",
			},
		},
		{
			Name:         "spdlog",
			Version:      "1.9.2",
			PURL:         "pkg:conan/spdlog@1.9.2",
			Locations:    fixtureLocationSet,
			Language:     pkg.CPP,
			Type:         pkg.ConanPkg,
			MetadataType: pkg.ConanMetadataType,
			Metadata: pkg.ConanMetadata{
				Ref: "spdlog/1.9.2",
			},
		},
		{
			Name:         "sdl",
			Version:      "2.0.20",
			PURL:         "pkg:conan/sdl@2.0.20",
			Locations:    fixtureLocationSet,
			Language:     pkg.CPP,
			Type:         pkg.ConanPkg,
			MetadataType: pkg.ConanMetadataType,
			Metadata: pkg.ConanMetadata{
				Ref: "sdl/2.0.20",
			},
		},
		{
			Name:         "fltk",
			Version:      "1.3.8",
			PURL:         "pkg:conan/fltk@1.3.8",
			Locations:    fixtureLocationSet,
			Language:     pkg.CPP,
			Type:         pkg.ConanPkg,
			MetadataType: pkg.ConanMetadataType,
			Metadata: pkg.ConanMetadata{
				Ref: "fltk/1.3.8",
			},
		},
	}

	// TODO: relationships are not under test
	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parseConanfile, expected, expectedRelationships)
}
