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
				Main: map[string]string{
					"Manifest-Version": "1.0",
				},
			},
		},
		{
			fixture: "test-fixtures/manifest/standard-info",
			expected: pkg.JavaManifest{
				Main: map[string]string{
					"Name":                   "the-best-name",
					"Manifest-Version":       "1.0",
					"Specification-Title":    "the-spec-title",
					"Specification-Version":  "the-spec-version",
					"Specification-Vendor":   "the-spec-vendor",
					"Implementation-Title":   "the-impl-title",
					"Implementation-Version": "the-impl-version",
					"Implementation-Vendor":  "the-impl-vendor",
				},
			},
		},
		{
			fixture: "test-fixtures/manifest/extra-info",
			expected: pkg.JavaManifest{
				Main: map[string]string{
					"Manifest-Version": "1.0",
					"Archiver-Version": "Plexus Archiver",
					"Created-By":       "Apache Maven 3.6.3",
				},
				NamedSections: map[string]map[string]string{
					"thing-1": {
						"Built-By": "?",
					},
					"1": {
						"Build-Jdk":  "14.0.1",
						"Main-Class": "hello.HelloWorld",
					},
				},
			},
		},
		{
			fixture: "test-fixtures/manifest/continuation",
			expected: pkg.JavaManifest{
				Main: map[string]string{
					"Manifest-Version": "1.0",
					"Plugin-ScmUrl":    "https://github.com/jenkinsci/plugin-pom/example-jenkins-plugin",
				},
			},
		},
		{
			// regression test, we should always keep the full version
			fixture: "test-fixtures/manifest/version-with-date",
			expected: pkg.JavaManifest{
				Main: map[string]string{
					"Manifest-Version":       "1.0",
					"Implementation-Version": "1.3 2244 October 5 2005",
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

			actual, err := parseJavaManifest(test.fixture, fixture)
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

func TestSelectName(t *testing.T) {
	tests := []struct {
		desc     string
		manifest pkg.JavaManifest
		archive  archiveFilename
		expected string
	}{
		{
			desc:    "Get name from Implementation-Title",
			archive: archiveFilename{},
			manifest: pkg.JavaManifest{
				Main: map[string]string{
					"Implementation-Title": "maven-wrapper",
				},
			},
			expected: "maven-wrapper",
		},
		{
			desc: "Implementation-Title does not override name from filename",
			manifest: pkg.JavaManifest{
				Main: map[string]string{
					"Name":                 "foo",
					"Implementation-Title": "maven-wrapper",
				},
			},
			archive:  newJavaArchiveFilename("/something/omg.jar"),
			expected: "omg",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			result := selectName(&test.manifest, test.archive)

			if result != test.expected {
				t.Errorf("mismatch in names: '%s' != '%s'", result, test.expected)
			}
		})
	}

}
