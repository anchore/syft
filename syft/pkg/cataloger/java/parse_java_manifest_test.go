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
				Main: pkg.KeyValues{
					{Key: "Manifest-Version", Value: "1.0"},
				},
			},
		},
		{
			fixture: "test-fixtures/manifest/standard-info",
			expected: pkg.JavaManifest{
				Main: pkg.KeyValues{
					{Key: "Manifest-Version", Value: "1.0"},
					{Key: "Name", Value: "the-best-name"},
					{Key: "Specification-Title", Value: "the-spec-title"},
					{Key: "Specification-Vendor", Value: "the-spec-vendor"},
					{Key: "Specification-Version", Value: "the-spec-version"},
					{Key: "Implementation-Title", Value: "the-impl-title"},
					{Key: "Implementation-Vendor", Value: "the-impl-vendor"},
					{Key: "Implementation-Version", Value: "the-impl-version"},
				},
			},
		},
		{
			fixture: "test-fixtures/manifest/extra-info",
			expected: pkg.JavaManifest{
				Main: []pkg.KeyValue{
					{
						Key:   "Manifest-Version",
						Value: "1.0",
					},
					{
						Key:   "Archiver-Version",
						Value: "Plexus Archiver",
					},
					{
						Key:   "Created-By",
						Value: "Apache Maven 3.6.3",
					},
				},
				Sections: []pkg.KeyValues{
					{
						{
							Key:   "Name",
							Value: "thing-1",
						},
						{
							Key:   "Built-By",
							Value: "?",
						},
					},
					{
						{
							Key:   "Build-Jdk",
							Value: "14.0.1",
						},
						{
							Key:   "Main-Class",
							Value: "hello.HelloWorld",
						},
					},
				},
			},
		},
		{
			fixture: "test-fixtures/manifest/extra-empty-lines",
			expected: pkg.JavaManifest{
				Main: pkg.KeyValues{
					{
						Key:   "Manifest-Version",
						Value: "1.0",
					},
					{
						Key:   "Archiver-Version",
						Value: "Plexus Archiver",
					},
					{
						Key:   "Created-By",
						Value: "Apache Maven 3.6.3",
					},
				},
				Sections: []pkg.KeyValues{
					{
						{Key: "Name", Value: "thing-1"},
						{Key: "Built-By", Value: "?"},
					},
					{
						{Key: "Name", Value: "thing-2"},
						{Key: "Built-By", Value: "someone!"},
					},
					{
						{Key: "Other", Value: "things"},
					},
					{
						{Key: "Last", Value: "item"},
					},
				},
			},
		},
		{
			fixture: "test-fixtures/manifest/continuation",
			expected: pkg.JavaManifest{
				Main: pkg.KeyValues{
					{
						Key:   "Manifest-Version",
						Value: "1.0",
					},
					{
						Key:   "Plugin-ScmUrl",
						Value: "https://github.com/jenkinsci/plugin-pom/example-jenkins-plugin",
					},
				},
			},
		},
		{
			// regression test, we should always keep the full version
			fixture: "test-fixtures/manifest/version-with-date",
			expected: pkg.JavaManifest{
				Main: []pkg.KeyValue{
					{
						Key:   "Manifest-Version",
						Value: "1.0",
					},
					{
						Key:   "Implementation-Version",
						Value: "1.3 2244 October 5 2005",
					},
				},
			},
		},
		{
			// regression test, we should not trim space and choke of empty space
			// https://github.com/anchore/syft/issues/2179
			fixture: "test-fixtures/manifest/leading-space",
			expected: pkg.JavaManifest{
				Main: []pkg.KeyValue{
					{
						Key:   "Key-keykeykey",
						Value: "initialconfig:com$    # aka not empty line",
					},
					{
						Key:   "should",
						Value: "parse",
					},
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
				Main: []pkg.KeyValue{
					{
						Key:   "Implementation-Title",
						Value: "maven-wrapper",
					},
				},
			},
			expected: "maven-wrapper",
		},
		{
			desc: "Implementation-Title does not override name from filename",
			manifest: pkg.JavaManifest{
				Main: []pkg.KeyValue{
					{
						Key:   "Name",
						Value: "foo",
					},
					{
						Key:   "Implementation-Title",
						Value: "maven-wrapper",
					},
				},
			},
			archive:  newJavaArchiveFilename("/something/omg.jar"),
			expected: "omg",
		},
		{
			desc: "Use the artifact ID baked by the Apache Maven Bundle Plugin",
			manifest: pkg.JavaManifest{
				Main: pkg.KeyValues{
					{Key: "Created-By", Value: "Apache Maven Bundle Plugin"},
					{Key: "Bundle-SymbolicName", Value: "com.atlassian.gadgets.atlassian-gadgets-api"},
					{Key: "Name", Value: "foo"},
					{Key: "Implementation-Title", Value: "maven-wrapper"},
				},
			},
			archive:  newJavaArchiveFilename("/something/omg.jar"),
			expected: "atlassian-gadgets-api",
		},
		{
			// example: pkg:maven/org.apache.servicemix.bundles/org.apache.servicemix.bundles.spring-beans@5.3.26_1
			desc: "Apache Maven Bundle Plugin might bake a version in the created-by field",
			manifest: pkg.JavaManifest{
				Main: pkg.KeyValues{
					{Key: "Created-By", Value: "Apache Maven Bundle Plugin 5.1.6"},
					{Key: "Bundle-SymbolicName", Value: "com.atlassian.gadgets.atlassian-gadgets-api"},
					{Key: "Name", Value: "foo"},
					{Key: "Implementation-Title", Value: "maven-wrapper"},
				},
			},
			archive:  newJavaArchiveFilename("/something/omg.jar"),
			expected: "atlassian-gadgets-api",
		},
		{
			desc: "Filename looks like a groupid + artifact id",
			manifest: pkg.JavaManifest{
				Main: []pkg.KeyValue{
					{
						Key:   "Name",
						Value: "foo",
					},
					{
						Key:   "Implementation-Title",
						Value: "maven-wrapper",
					},
				},
			},
			archive:  newJavaArchiveFilename("/something/com.atlassian.gadgets.atlassian-gadgets-api.jar"),
			expected: "atlassian-gadgets-api",
		},
		{
			desc:     "Filename has period that is not groupid + artifact id",
			manifest: pkg.JavaManifest{},
			archive:  newJavaArchiveFilename("/something/http4s-crypto_2.12-0.1.0.jar"),
			expected: "http4s-crypto_2.12",
		},
		{
			desc:     "Filename has period that is not groupid + artifact id, kafka",
			manifest: pkg.JavaManifest{},
			archive:  newJavaArchiveFilename("/something//kafka_2.13-3.2.2.jar"),
			expected: "kafka_2.13", // see https://mvnrepository.com/artifact/org.apache.kafka/kafka_2.13/3.2.2
		},
		{
			desc: "Skip stripping groupId prefix from archive filename for org.eclipse",
			manifest: pkg.JavaManifest{
				Main: []pkg.KeyValue{
					{
						Key:   "Automatic-Module-Name",
						Value: "org.eclipse.ant.core",
					},
				},
			},
			archive:  newJavaArchiveFilename("/something/org.eclipse.ant.core-3.7.0.jar"),
			expected: "org.eclipse.ant.core",
		},
		{
			// example: pkg:maven/com.google.oauth-client/google-oauth-client@1.25.0
			desc: "skip Apache Maven Bundle Plugin logic if symbolic name is same as vendor id",
			manifest: pkg.JavaManifest{
				Main: pkg.KeyValues{
					{Key: "Bundle-DocURL", Value: "http://www.google.com/"},
					{Key: "Bundle-License", Value: "http://www.apache.org/licenses/LICENSE-2.0.txt"},
					{Key: "Bundle-ManifestVersion", Value: "2"},
					{Key: "Bundle-Name", Value: "Google OAuth Client Library for Java"},
					{Key: "Bundle-RequiredExecutionEnvironment", Value: "JavaSE-1.6"},
					{Key: "Bundle-SymbolicName", Value: "com.google.oauth-client"},
					{Key: "Bundle-Vendor", Value: "Google"},
					{Key: "Bundle-Version", Value: "1.25.0"},
					{Key: "Created-By", Value: "Apache Maven Bundle Plugin"},
					{Key: "Export-Package", Value: "com.google.api.client.auth.openidconnect;uses:=\"com.google.api.client.auth.oauth2,com.google.api.client.json,com.google.api.client.json.webtoken,com.google.api.client.util\";version=\"1.25.0\",com.google.api.client.auth.oauth;uses:=\"com.google.api.client.http,com.google.api.client.util\";version=\"1.25.0\",com.google.api.client.auth.oauth2;uses:=\"com.google.api.client.http,com.google.api.client.json,com.google.api.client.util,com.google.api.client.util.store\";version=\"1.25.0\""},
					{Key: "Implementation-Title", Value: "Google OAuth Client Library for Java"},
					{Key: "Implementation-Vendor", Value: "Google"},
					{Key: "Implementation-Vendor-Id", Value: "com.google.oauth-client"},
					{Key: "Implementation-Version", Value: "1.25.0"},
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
				Main: []pkg.KeyValue{
					{
						Key:   "Implementation-Version",
						Value: "1.8.2",
					},
				},
			},
			expected: "1.8.2",
		},
		{
			name: "Implementation-Version takes precedence over Specification-Version",
			manifest: pkg.JavaManifest{
				Main: []pkg.KeyValue{
					{
						Key:   "Implementation-Version",
						Value: "1.8.2",
					},
					{
						Key:   "Specification-Version",
						Value: "1.0",
					},
				},
			},
			expected: "1.8.2",
		},
		{
			name: "Implementation-Version found outside the main section",
			manifest: pkg.JavaManifest{
				Main: pkg.KeyValues{
					{Key: "Manifest-Version", Value: "1.0"},
					{Key: "Ant-Version", Value: "Apache Ant 1.8.2"},
					{Key: "Created-By", Value: "1.5.0_22-b03 (Sun Microsystems Inc.)"},
				},
				Sections: []pkg.KeyValues{
					{
						{Key: "Name", Value: "org/apache/tools/ant/taskdefs/optional/"},
						{Key: "Implementation-Version", Value: "1.8.2"},
					},
				},
			},
			expected: "1.8.2",
		},
		{
			name: "Implementation-Version takes precedence over Specification-Version in subsequent section",
			manifest: pkg.JavaManifest{
				Main: pkg.KeyValues{
					{Key: "Manifest-Version", Value: "1.0"},
					{Key: "Ant-Version", Value: "Apache Ant 1.8.2"},
					{Key: "Created-By", Value: "1.5.0_22-b03 (Sun Microsystems Inc.)"},
					{Key: "Specification-Version", Value: "2.0"},
				},
				Sections: []pkg.KeyValues{
					{
						{Key: "Name", Value: "org/apache/tools/ant/taskdefs/optional/"},
						{Key: "Specification-Version", Value: "1.8"},
					},
					{
						{Key: "Name", Value: "some-other-section"},
						{Key: "Implementation-Version", Value: "1.8.2"},
					},
				},
			},

			expected: "1.8.2",
		},
		{
			name: "Implementation-Version takes precedence over Specification-Version in subsequent section",
			manifest: pkg.JavaManifest{
				Main: []pkg.KeyValue{
					{
						Key:   "Manifest-Version",
						Value: "1.0",
					},
					{
						Key:   "Ant-Version",
						Value: "Apache Ant 1.8.2",
					},
					{
						Key:   "Created-By",
						Value: "1.5.0_22-b03 (Sun Microsystems Inc.)",
					},
				},
				Sections: []pkg.KeyValues{
					{
						{
							Key:   "Name",
							Value: "some-other-section",
						},
						{
							Key:   "Bundle-Version",
							Value: "1.11.28",
						},
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
