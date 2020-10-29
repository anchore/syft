package java

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
)

func TestParseJavaManifest(t *testing.T) {
	tests := []struct {
		fixture  string
		expected pkg.JavaManifest
	}{
		{
			fixture: "test-fixtures/manifest/small",
			expected: pkg.JavaManifest{
				ManifestVersion: "1.0",
			},
		},
		{
			fixture: "test-fixtures/manifest/standard-info",
			expected: pkg.JavaManifest{
				ManifestVersion: "1.0",
				Name:            "the-best-name",
				SpecTitle:       "the-spec-title",
				SpecVersion:     "the-spec-version",
				SpecVendor:      "the-spec-vendor",
				ImplTitle:       "the-impl-title",
				ImplVersion:     "the-impl-version",
				ImplVendor:      "the-impl-vendor",
			},
		},
		{
			fixture: "test-fixtures/manifest/extra-info",
			expected: pkg.JavaManifest{
				ManifestVersion: "1.0",
				Extra: map[string]string{
					"Archiver-Version": "Plexus Archiver",
					"Created-By":       "Apache Maven 3.6.3",
				},
				Sections: []map[string]string{
					{
						"Built-By": "?",
					},
					{
						"Build-Jdk":  "14.0.1",
						"Main-Class": "hello.HelloWorld",
					},
				},
			},
		},
		{
			fixture: "test-fixtures/manifest/continuation",
			expected: pkg.JavaManifest{
				ManifestVersion: "1.0",
				Extra: map[string]string{
					"Plugin-ScmUrl": "https://github.com/jenkinsci/plugin-pom/example-jenkins-plugin",
				},
			},
		},
		{
			// regression test, we should always keep the full version
			fixture: "test-fixtures/manifest/version-with-date",
			expected: pkg.JavaManifest{
				ManifestVersion: "1.0",
				ImplVersion:     "1.3 2244 October 5 2005",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			fixture, err := os.Open(test.fixture)
			if err != nil {
				t.Fatalf("could not open fixture: %+v", err)
			}

			actual, err := parseJavaManifest(fixture)
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
