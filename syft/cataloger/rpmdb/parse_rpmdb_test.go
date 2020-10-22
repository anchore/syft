package rpmdb

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
)

func TestParseRpmDB(t *testing.T) {
	expected := map[string]pkg.Package{
		"dive": {
			Name:         "dive",
			Version:      "0.9.2-1",
			Type:         pkg.RpmPkg,
			MetadataType: pkg.RpmdbMetadataType,
			Metadata: pkg.RpmdbMetadata{
				Name:      "dive",
				Epoch:     0,
				Arch:      "x86_64",
				Release:   "1",
				Version:   "0.9.2",
				SourceRpm: "dive-0.9.2-1.src.rpm",
				Size:      12406784,
				License:   "MIT",
				Vendor:    "",
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

	if len(actual) != len(expected) {
		for _, a := range actual {
			t.Log("   ", a)
		}
		t.Fatalf("unexpected package count: %d!=%d", len(actual), len(expected))
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
