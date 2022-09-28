package cpp

import (
	"os"
	"testing"

	"github.com/go-test/deep"

	"github.com/anchore/syft/syft/pkg"
)

func TestParseConanlock(t *testing.T) {
	expected := []*pkg.Package{
		{
			Name:         "zlib",
			Version:      "1.2.12",
			Language:     pkg.CPP,
			Type:         pkg.ConanPkg,
			MetadataType: pkg.ConanaMetadataType,
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
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	// TODO: no relationships are under test yet
	actual, _, err := parseConanlock(fixture.Name(), fixture)
	if err != nil {
		t.Error(err)
	}

	differences := deep.Equal(expected, actual)
	if differences != nil {
		t.Errorf("returned package list differed from expectation: %+v", differences)
	}
}
