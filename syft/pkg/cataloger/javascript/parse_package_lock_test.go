package javascript

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func assertPkgsEqual(t *testing.T, actual []*pkg.Package, expected map[string]pkg.Package) {
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
		assert.Equal(t, expectedPkg.Version, a.Version, "bad version")
		assert.Equal(t, expectedPkg.Language, a.Language, "bad language")
		assert.Equal(t, expectedPkg.Type, a.Type, "bad type")
		assert.Equal(t, expectedPkg.Licenses, a.Licenses, "bad license count")
	}
}

func TestParsePackageLock(t *testing.T) {
	expected := map[string]pkg.Package{
		"@types/prop-types": {
			Name:     "@types/prop-types",
			Version:  "15.7.5",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
			Licenses: []string{"MIT"},
		},
		"@types/react": {
			Name:     "@types/prop-types",
			Version:  "18.0.17",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
			Licenses: []string{"MIT"},
		},
		"@types/scheduler": {
			Name:     "@types/scheduler",
			Version:  "0.16.2",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
			Licenses: []string{"MIT"},
		},
		"csstype": {
			Name:     "csstype",
			Version:  "3.1.0",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
			Licenses: []string{"MIT"},
		},
	}
	fixture, err := os.Open("test-fixtures/pkg-lock/package-lock-2.json")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	// TODO: no relationships are under test yet
	actual, _, err := parsePackageLock(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse package-lock.json: %+v", err)
	}

	assertPkgsEqual(t, actual, expected)
}
