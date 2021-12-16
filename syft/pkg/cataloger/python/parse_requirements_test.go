package python

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-test/deep"

	"github.com/anchore/syft/syft/pkg"
)

func assertPackagesEqual(t *testing.T, actual []*pkg.Package, expected map[string]pkg.Package) {
	t.Helper()
	if len(actual) != len(expected) {
		for _, a := range actual {
			t.Log("   ", a)
		}
		t.Fatalf("unexpected package count: %d!=%d", len(actual), len(expected))
	}

	for _, a := range actual {
		expectedPkg, ok := expected[a.Name]
		assert.True(t, ok)

		for _, d := range deep.Equal(a, &expectedPkg) {
			t.Errorf("diff: %+v", d)
		}
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	expected := map[string]pkg.Package{
		"foo": {
			Name:     "foo",
			Version:  "1.0.0",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
		},
		"flask": {
			Name:     "flask",
			Version:  "4.0.0",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
		},
	}
	fixture, err := os.Open("test-fixtures/requires/requirements.txt")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	// TODO: no relationships are under test yet
	actual, _, err := parseRequirementsTxt(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse requirements: %+v", err)
	}

	assertPackagesEqual(t, actual, expected)

}
