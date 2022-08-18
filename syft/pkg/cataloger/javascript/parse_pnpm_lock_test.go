package javascript

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
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

	differences := deep.Equal(expected, actual)
	if differences != nil {
		t.Errorf("returned package list differed from expectation: %+v", differences)
	}
}
