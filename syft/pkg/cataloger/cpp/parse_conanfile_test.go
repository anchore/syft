package cpp

import (
	"os"
	"testing"

	"github.com/go-test/deep"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func TestParseConanfile(t *testing.T) {
	expected := []pkg.Package{
		{
			Name:         "catch2",
			Version:      "2.13.8",
			PURL:         "pkg:conan/catch2@2.13.8",
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
			Language:     pkg.CPP,
			Type:         pkg.ConanPkg,
			MetadataType: pkg.ConanMetadataType,
			Metadata: pkg.ConanMetadata{
				Ref: "fltk/1.3.8",
			},
		},
	}

	fixture, err := os.Open("test-fixtures/conanfile.txt")
	require.NoError(t, err)

	// TODO: no relationships are under test yet
	actual, _, err := parseConanfile(nil, nil, source.LocationReadCloser{
		Location:   source.NewLocation(fixture.Name()),
		ReadCloser: fixture,
	})
	require.NoError(t, err)

	differences := deep.Equal(expected, actual)
	if differences != nil {
		t.Errorf("returned package list differed from expectation: %+v", differences)
	}
}
