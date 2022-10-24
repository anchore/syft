package cpp

import (
	"os"
	"testing"

	"github.com/go-test/deep"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func TestParseConanlock(t *testing.T) {
	expected := []pkg.Package{
		{
			Name:         "zlib",
			Version:      "1.2.12",
			PURL:         "pkg:conan/zlib@1.2.12",
			Language:     pkg.CPP,
			Type:         pkg.ConanPkg,
			MetadataType: pkg.ConanLockMetadataType,
			Metadata: pkg.ConanLockMetadata{
				Ref: "zlib/1.2.12",
				Options: map[string]string{
					"fPIC":   "True",
					"shared": "False",
				},
				Path:    "all/conanfile.py",
				Context: "host",
			},
		},
	}

	fixture, err := os.Open("test-fixtures/conan.lock")
	require.NoError(t, err)

	// TODO: no relationships are under test yet
	actual, _, err := parseConanlock(nil, nil, source.LocationReadCloser{
		Location:   source.NewLocation(fixture.Name()),
		ReadCloser: fixture,
	})
	require.NoError(t, err)

	differences := deep.Equal(expected, actual)
	if differences != nil {
		t.Errorf("returned package list differed from expectation: %+v", differences)
	}
}
