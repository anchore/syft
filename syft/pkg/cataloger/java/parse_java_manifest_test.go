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
		{
			// regression test, we should not trim space and choke of empty space
			// https://github.com/anchore/syft/issues/2179
			fixture: "test-fixtures/manifest/leading-space",
			expected: pkg.JavaManifest{
				Main: map[string]string{
					"Key-keykeykey": "initialconfig:com$    # aka not empty line",
					"should":        "parse",
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
		{
			desc: "Use the artifact ID baked by the Apache Maven Bundle Plugin",
			manifest: pkg.JavaManifest{
				Main: map[string]string{
					"Created-By":           "Apache Maven Bundle Plugin",
					"Bundle-SymbolicName":  "com.atlassian.gadgets.atlassian-gadgets-api",
					"Name":                 "foo",
					"Implementation-Title": "maven-wrapper",
				},
			},
			archive:  newJavaArchiveFilename("/something/omg.jar"),
			expected: "atlassian-gadgets-api",
		},
		{
			// example: pkg:maven/org.apache.servicemix.bundles/org.apache.servicemix.bundles.spring-beans@5.3.26_1
			desc: "Apache Maven Bundle Plugin might bake a version in the created-by field",
			manifest: pkg.JavaManifest{
				Main: map[string]string{
					"Created-By":           "Apache Maven Bundle Plugin 5.1.6",
					"Bundle-SymbolicName":  "com.atlassian.gadgets.atlassian-gadgets-api",
					"Name":                 "foo",
					"Implementation-Title": "maven-wrapper",
				},
			},
			archive:  newJavaArchiveFilename("/something/omg.jar"),
			expected: "atlassian-gadgets-api",
		},
		{
			desc: "Filename looks like a groupid + artifact id",
			manifest: pkg.JavaManifest{
				Main: map[string]string{
					"Name":                 "foo",
					"Implementation-Title": "maven-wrapper",
				},
			},
			archive:  newJavaArchiveFilename("/something/com.atlassian.gadgets.atlassian-gadgets-api.jar"),
			expected: "atlassian-gadgets-api",
		},
		{
			desc: "Skip stripping groupId prefix from archive filename for org.eclipse",
			manifest: pkg.JavaManifest{
				Main: map[string]string{
					"Automatic-Module-Name": "org.eclipse.ant.core",
				},
			},
			archive:  newJavaArchiveFilename("/something/org.eclipse.ant.core-3.7.0.jar"),
			expected: "org.eclipse.ant.core",
		},
		{
			// example: pkg:maven/com.google.oauth-client/google-oauth-client@1.25.0
			desc: "skip Apache Maven Bundle Plugin logic if symbolic name is same as vendor id",
			manifest: pkg.JavaManifest{
				Main: map[string]string{
					"Bundle-DocURL":                       "http://www.google.com/",
					"Bundle-License":                      "http://www.apache.org/licenses/LICENSE-2.0.txt",
					"Bundle-ManifestVersion":              "2",
					"Bundle-Name":                         "Google OAuth Client Library for Java",
					"Bundle-RequiredExecutionEnvironment": "JavaSE-1.6",
					"Bundle-SymbolicName":                 "com.google.oauth-client",
					"Bundle-Vendor":                       "Google",
					"Bundle-Version":                      "1.25.0",
					"Created-By":                          "Apache Maven Bundle Plugin",
					"Export-Package":                      "com.google.api.client.auth.openidconnect;uses:=\"com.google.api.client.auth.oauth2,com.google.api.client.json,com.google.api.client.json.webtoken,com.google.api.client.util\";version=\"1.25.0\",com.google.api.client.auth.oauth;uses:=\"com.google.api.client.http,com.google.api.client.util\";version=\"1.25.0\",com.google.api.client.auth.oauth2;uses:=\"com.google.api.client.http,com.google.api.client.json,com.google.api.client.util,com.google.api.client.util.store\";version=\"1.25.0\"",
					"Implementation-Title":                "Google OAuth Client Library for Java",
					"Implementation-Vendor":               "Google",
					"Implementation-Vendor-Id":            "com.google.oauth-client",
					"Implementation-Version":              "1.25.0",
				},
			},
			archive:  newJavaArchiveFilename("/something/google-oauth-client-1.25.0.jar"),
			expected: "google-oauth-client",
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
