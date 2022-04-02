package golang

import (
	"os"
	"testing"

	"github.com/go-test/deep"

	"github.com/anchore/syft/syft/pkg"
)

func TestParseGoMod(t *testing.T) {
	tests := []struct {
		fixture  string
		expected map[string]pkg.Package
	}{
		{
			fixture: "test-fixtures/one-package",
			expected: map[string]pkg.Package{
				"github.com/bmatcuk/doublestar": {
					Name:     "github.com/bmatcuk/doublestar",
					Version:  "v1.3.1",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
				},
			},
		},
		{

			fixture: "test-fixtures/many-packages",
			expected: map[string]pkg.Package{
				"github.com/anchore/go-testutils": {
					Name:     "github.com/anchore/go-testutils",
					Version:  "v0.0.0-20200624184116-66aa578126db",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
				},
				"github.com/anchore/go-version": {
					Name:     "github.com/anchore/go-version",
					Version:  "v1.2.2-0.20200701162849-18adb9c92b9b",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
				},
				"github.com/anchore/stereoscope": {
					Name:     "github.com/anchore/stereoscope",
					Version:  "v0.0.0-20200706164556-7cf39d7f4639",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
				},
				"github.com/bmatcuk/doublestar": {
					Name:     "github.com/bmatcuk/doublestar",
					Version:  "v8.8.8",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
				},
				"github.com/go-test/deep": {
					Name:     "github.com/go-test/deep",
					Version:  "v1.0.6",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			f, err := os.Open(test.fixture)
			if err != nil {
				t.Fatalf(err.Error())
			}

			// TODO: no relationships are under test yet
			actual, _, err := parseGoMod(test.fixture, f)
			if err != nil {
				t.Fatalf(err.Error())
			}

			if len(actual) != len(test.expected) {
				t.Fatalf("unexpected length: %d", len(actual))
			}

			for _, a := range actual {
				e, ok := test.expected[a.Name]
				if !ok {
					t.Errorf("extra package: %s", a.Name)
					continue
				}

				diffs := deep.Equal(a, &e)
				if len(diffs) > 0 {
					t.Errorf("diffs found for %q", a.Name)
					for _, d := range diffs {
						t.Errorf("diff: %+v", d)
					}
				}
			}

			if t.Failed() {
				for _, a := range actual {
					t.Logf("Found: %+v", a)
				}
			}

		})
	}
}
