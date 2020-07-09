package java

import (
	"encoding/json"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/go-test/deep"
	"os"
	"testing"
)

func TestParseJavaPomProperties(t *testing.T) {
	tests := []struct {
		fixture  string
		expected pkg.PomProperties
	}{
		{
			fixture: "test-fixtures/pom/small.pom.properties",
			expected: pkg.PomProperties{
				Path:       "test-fixtures/pom/small.pom.properties",
				GroupID:    "org.anchore",
				ArtifactID: "example-java-app-maven",
				Version:    "0.1.0",
			},
		},
		{
			fixture: "test-fixtures/pom/extra.pom.properties",
			expected: pkg.PomProperties{
				Path:       "test-fixtures/pom/extra.pom.properties",
				GroupID:    "org.anchore",
				ArtifactID: "example-java-app-maven",
				Version:    "0.1.0",
				Name:       "something-here",
				Extra: map[string]string{
					"another": "thing",
					"sweet":   "work",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			fixture, err := os.Open(test.fixture)
			if err != nil {
				t.Fatalf("could not open fixture: %+v", err)
			}

			actual, err := parsePomProperties(fixture.Name(), fixture)
			if err != nil {
				t.Fatalf("failed to parse manifest: %+v", err)
			}

			diffs := deep.Equal(actual, &test.expected)
			if len(diffs) > 0 {
				for _, d := range diffs {
					t.Errorf("diff: %+v", d)
				}

				b, err := json.MarshalIndent(actual, "", "  ")
				if err != nil {
					t.Fatalf("can't show results: %+v", err)
				}

				t.Errorf("full result: %s", string(b))
			}
		})
	}
}
