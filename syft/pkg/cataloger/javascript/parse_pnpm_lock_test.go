package javascript

import (
	"os"
	"sort"
	"testing"

	"github.com/go-test/deep"

	"github.com/anchore/syft/syft/pkg"
)

func fixtureP(str string) *string {
	return &str
}

func TestParsePnpmLock(t *testing.T) {
	expected := []*pkg.Package{
		{
			Name:     "nanoid",
			Version:  "3.3.4",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		{
			Name:     "picocolors",
			Version:  "1.0.0",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		{
			Name:     "source-map-js",
			Version:  "1.0.2",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
	}

	fixture, err := os.Open("test-fixtures/pnpm/pnpm-lock.yaml")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	// TODO: no relationships are under test yet
	actual, _, err := parsePnpmLock(fixture.Name(), fixture)
	if err != nil {
		t.Error(err)
	}

	// we have to sort this for expected to match actual since yaml maps are unordered
	sort.Slice(actual, func(p, q int) bool {
		return actual[p].Name < actual[q].Name
	})

	differences := deep.Equal(expected, actual)
	if differences != nil {
		t.Errorf("returned package list differed from expectation: %+v", differences)
	}
}
