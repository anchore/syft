package rpmdb

import (
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/go-test/deep"
	"os"
	"testing"
)

func TestParseRpmDB(t *testing.T) {
	expected := map[string]pkg.Package{
		"dive": {
			Name:    "dive",
			Version: "0.9.2",
			Type:    pkg.RpmPkg,
			Metadata: pkg.RpmMetadata{
				Epoch:   0,
				Arch:    "x86_64",
				Release: "1",
			},
		},
	}

	fixture, err := os.Open("test-fixtures/Packages")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	actual, err := parseRpmDB(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse rpmdb: %+v", err)
	}

	if len(actual) != 1 {
		for _, a := range actual {
			t.Log("   ", a)
		}
		t.Fatalf("unexpected package count: %d!=%d", len(actual), 1)
	}

	for _, a := range actual {
		e := expected[a.Name]
		diffs := deep.Equal(a, e)
		if len(diffs) > 0 {
			for _, d := range diffs {
				t.Errorf("diff: %+v", d)
			}
		}
	}
}
