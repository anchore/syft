package java

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/go-test/deep"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
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
			fixture: "test-fixtures/manifest/extra-empty-lines",
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
					"thing-2": {
						"Built-By": "someone!",
					},
					"2": {
						"Other": "things",
					},
					"3": {
						"Last": "item",
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

func TestSelectVersion(t *testing.T) {
	tests := []struct {
		name     string
		manifest pkg.JavaManifest
		archive  archiveFilename
		expected string
	}{
		{
			name:    "Get name from Implementation-Version",
			archive: archiveFilename{},
			manifest: pkg.JavaManifest{
				Main: map[string]string{
					"Implementation-Version": "1.8.2",
				},
			},
			expected: "1.8.2",
		},
		{
			name: "Implementation-Version takes precedence over Specification-Version",
			manifest: pkg.JavaManifest{
				Main: map[string]string{
					"Implementation-Version": "1.8.2",
					"Specification-Version":  "1.0",
				},
			},
			expected: "1.8.2",
		},
		{
			name: "Implementation-Version found outside the main section",
			manifest: pkg.JavaManifest{
				Main: map[string]string{
					"Manifest-Version": "1.0",
					"Ant-Version":      "Apache Ant 1.8.2",
					"Created-By":       "1.5.0_22-b03 (Sun Microsystems Inc.)",
				},
				NamedSections: map[string]map[string]string{
					"org/apache/tools/ant/taskdefs/optional/": {
						"Implementation-Version": "1.8.2",
					},
				},
			},
			expected: "1.8.2",
		},
		{
			name: "Implementation-Version takes precedence over Specification-Version in subsequent section",
			manifest: pkg.JavaManifest{
				Main: map[string]string{
					"Manifest-Version":      "1.0",
					"Ant-Version":           "Apache Ant 1.8.2",
					"Created-By":            "1.5.0_22-b03 (Sun Microsystems Inc.)",
					"Specification-Version": "2.0",
				},
				NamedSections: map[string]map[string]string{
					"org/apache/tools/ant/taskdefs/optional/": {
						"Specification-Version": "1.8",
					},
					"some-other-section": {
						"Implementation-Version": "1.8.2",
					},
				},
			},
			expected: "1.8.2",
		},
		{
			name: "Implementation-Version takes precedence over Specification-Version in subsequent section",
			manifest: pkg.JavaManifest{
				Main: map[string]string{
					"Manifest-Version": "1.0",
					"Ant-Version":      "Apache Ant 1.8.2",
					"Created-By":       "1.5.0_22-b03 (Sun Microsystems Inc.)",
				},
				NamedSections: map[string]map[string]string{
					"some-other-section": {
						"Bundle-Version": "1.11.28",
					},
				},
			},
			expected: "1.11.28",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := selectVersion(&test.manifest, test.archive)

			assert.Equal(t, test.expected, result)
		})
	}
}
