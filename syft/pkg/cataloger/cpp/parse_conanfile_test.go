package cpp

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
)

func TestParseConanfile(t *testing.T) {
	expected := []*pkg.Package{
		{
			Name:         "catch2",
			Version:      "2.13.8",
			Language:     pkg.CPP,
			Type:         pkg.ConanPkg,
			MetadataType: pkg.ConanaMetadataType,
			Metadata: pkg.ConanMetadata{
				Name:    "catch2",
				Version: "2.13.8",
			},
		},
		{
			Name:         "docopt.cpp",
			Version:      "0.6.3",
			Language:     pkg.CPP,
			Type:         pkg.ConanPkg,
			MetadataType: pkg.ConanaMetadataType,
			Metadata: pkg.ConanMetadata{
				Name:    "docopt.cpp",
				Version: "0.6.3",
			},
		},
		{
			Name:         "fmt",
			Version:      "8.1.1",
			Language:     pkg.CPP,
			Type:         pkg.ConanPkg,
			MetadataType: pkg.ConanaMetadataType,
			Metadata: pkg.ConanMetadata{
				Name:    "fmt",
				Version: "8.1.1",
			},
		},
		{
			Name:         "spdlog",
			Version:      "1.9.2",
			Language:     pkg.CPP,
			Type:         pkg.ConanPkg,
			MetadataType: pkg.ConanaMetadataType,
			Metadata: pkg.ConanMetadata{
				Name:    "spdlog",
				Version: "1.9.2",
			},
		},
		{
			Name:         "sdl",
			Version:      "2.0.20",
			Language:     pkg.CPP,
			Type:         pkg.ConanPkg,
			MetadataType: pkg.ConanaMetadataType,
			Metadata: pkg.ConanMetadata{
				Name:    "sdl",
				Version: "2.0.20",
			},
		},
		{
			Name:         "fltk",
			Version:      "1.3.8",
			Language:     pkg.CPP,
			Type:         pkg.ConanPkg,
			MetadataType: pkg.ConanaMetadataType,
			Metadata: pkg.ConanMetadata{
				Name:    "fltk",
				Version: "1.3.8",
			},
		},
	}

	fixture, err := os.Open("test-fixtures/conanfile.txt")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	// TODO: no relationships are under test yet
	actual, _, err := parseConanfile(fixture.Name(), fixture)
	if err != nil {
		t.Error(err)
	}

	differences := deep.Equal(expected, actual)
	if differences != nil {
		t.Errorf("returned package list differed from expectation: %+v", differences)
	}
}
