package bundler

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
)

func TestParseGemspec(t *testing.T) {
	var expectedGems = map[string]string{
		"bundler": "2.1.4",
	}

	fixture, err := os.Open("test-fixtures/bundler.gemspec")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	actual, err := parseGemSpecEntries(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse gemspec: %+v", err)
	}

	if len(actual) != len(expectedGems) {
		for _, a := range actual {
			t.Log("   ", a)
		}
		t.Fatalf("unexpected package count: %d!=%d", len(actual), len(expectedGems))
	}

	for _, a := range actual {
		expectedVersion, ok := expectedGems[a.Name]
		if !ok {
			t.Errorf("unexpected package found: %s", a.Name)
		}

		if expectedVersion != a.Version {
			t.Errorf("unexpected package version (pkg=%s): %s", a.Name, a.Version)
		}

		if a.Language != pkg.Ruby {
			t.Errorf("bad language (pkg=%+v): %+v", a.Name, a.Language)
		}

		if a.Type != pkg.GemPkg {
			t.Errorf("bad package type (pkg=%+v): %+v", a.Name, a.Type)
		}
	}
}
