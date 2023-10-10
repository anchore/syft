package java

import (
	"encoding/base64"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vifraa/gopom"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_parserPomXML(t *testing.T) {
	tests := []struct {
		input    string
		expected []pkg.Package
	}{
		{
			input: "test-fixtures/pom/pom.xml",
			expected: []pkg.Package{
				{
					Name:         "joda-time",
					Version:      "2.9.2",
					PURL:         "pkg:maven/com.joda/joda-time@2.9.2",
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PomProperties: &pkg.PomProperties{
							GroupID:    "com.joda",
							ArtifactID: "joda-time",
						},
					},
				},
				{
					Name:         "junit",
					Version:      "4.12",
					PURL:         "pkg:maven/junit/junit@4.12",
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PomProperties: &pkg.PomProperties{
							GroupID:    "junit",
							ArtifactID: "junit",
							Scope:      "test",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			for i := range test.expected {
				test.expected[i].Locations.Add(file.NewLocation(test.input))
			}
			pkgtest.TestFileParser(t, test.input, parserPomXML, test.expected, nil)
		})
	}
}

func Test_decodePomXML_surviveNonUtf8Encoding(t *testing.T) {
	// regression for https://github.com/anchore/syft/issues/2044

	// we are storing the base64 contents of the pom.xml file. We are doing this to prevent accidental changes to the
	// file, which is extremely important for this test.

	// for instance, even changing a single character in the file and saving in an IntelliJ IDE will automatically
	// convert the file to UTF-8, which will break this test:

	// xxd with the original pom.xml
	// 00000780: 6964 3e0d 0a20 2020 2020 2020 2020 2020  id>..
	// 00000790: 203c 6e61 6d65 3e4a e972 f46d 6520 4d69   <name>J.r.me Mi
	// 000007a0: 7263 3c2f 6e61 6d65 3e0d 0a20 2020 2020  rc</name>..

	// xxd with the pom.xml converted to UTF-8 (from a simple change with IntelliJ)
	// 00000780: 6964 3e0d 0a20 2020 2020 2020 2020 2020  id>..
	// 00000790: 203c 6e61 6d65 3e4a efbf bd72 efbf bd6d   <name>J...r...m
	// 000007a0: 6520 4d69 7263 3c2f 6e61 6d65 3e0d 0a20  e Mirc</name>..

	// Note that the name "Jérôme Mirc" was originally interpreted as "J.r.me Mi" and after the save
	// is now encoded as "J...r...m" which is not what we want (note the extra bytes for each non UTF-8 character.
	// The original 0xe9 byte (é) was converted to 0xefbfbd (�) which is the UTF-8 replacement character.
	// This is quite silly on the part of IntelliJ, but it is what it is.

	cases := []struct {
		name    string
		fixture string
	}{
		{
			name:    "undeclared encoding",
			fixture: "test-fixtures/pom/undeclared-iso-8859-encoded-pom.xml.base64",
		},
		{
			name:    "declared encoding",
			fixture: "test-fixtures/pom/declared-iso-8859-encoded-pom.xml.base64",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fh, err := os.Open(c.fixture)
			require.NoError(t, err)

			decoder := base64.NewDecoder(base64.StdEncoding, fh)

			proj, err := decodePomXML(decoder)

			require.NoError(t, err)
			require.NotEmpty(t, proj.Developers)
		})
	}

}

func Test_parseCommonsTextPomXMLProject(t *testing.T) {
	tests := []struct {
		input    string
		expected []pkg.Package
	}{
		{
			input: "test-fixtures/pom/commons-text.pom.xml",
			expected: []pkg.Package{
				{
					Name:         "commons-lang3",
					Version:      "3.12.0",
					PURL:         "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PomProperties: &pkg.PomProperties{
							GroupID:    "org.apache.commons",
							ArtifactID: "commons-lang3",
						},
					},
				},
				{
					Name:         "junit-jupiter",
					Version:      "",
					PURL:         "pkg:maven/org.junit.jupiter/junit-jupiter",
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PomProperties: &pkg.PomProperties{
							GroupID:    "org.junit.jupiter",
							ArtifactID: "junit-jupiter",
							Scope:      "test",
						},
					},
				},
				{
					Name:         "assertj-core",
					Version:      "3.23.1",
					PURL:         "pkg:maven/org.assertj/assertj-core@3.23.1",
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PomProperties: &pkg.PomProperties{
							GroupID:    "org.assertj",
							ArtifactID: "assertj-core",
							Scope:      "test",
						},
					},
				},
				{
					Name:         "commons-io",
					Version:      "2.11.0",
					PURL:         "pkg:maven/commons-io/commons-io@2.11.0",
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PomProperties: &pkg.PomProperties{
							GroupID:    "commons-io",
							ArtifactID: "commons-io",
							Scope:      "test",
						},
					},
				},
				{
					Name:         "mockito-inline",
					Version:      "4.8.0",
					PURL:         "pkg:maven/org.mockito/mockito-inline@4.8.0",
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PomProperties: &pkg.PomProperties{
							GroupID:    "org.mockito",
							ArtifactID: "mockito-inline",
							Scope:      "test",
						},
					},
				},
				{
					Name:         "js",
					Version:      "22.0.0.2",
					PURL:         "pkg:maven/org.graalvm.js/js@22.0.0.2",
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PomProperties: &pkg.PomProperties{
							GroupID:    "org.graalvm.js",
							ArtifactID: "js",
							Scope:      "test",
						},
					},
				},
				{
					Name:         "js-scriptengine",
					Version:      "22.0.0.2",
					PURL:         "pkg:maven/org.graalvm.js/js-scriptengine@22.0.0.2",
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PomProperties: &pkg.PomProperties{
							GroupID:    "org.graalvm.js",
							ArtifactID: "js-scriptengine",
							Scope:      "test",
						},
					},
				},
				{
					Name:         "commons-rng-simple",
					Version:      "1.4",
					PURL:         "pkg:maven/org.apache.commons/commons-rng-simple@1.4",
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PomProperties: &pkg.PomProperties{
							GroupID:    "org.apache.commons",
							ArtifactID: "commons-rng-simple",
							Scope:      "test",
						},
					},
				},
				{
					Name:         "jmh-core",
					Version:      "1.35",
					PURL:         "pkg:maven/org.openjdk.jmh/jmh-core@1.35",
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PomProperties: &pkg.PomProperties{
							GroupID:    "org.openjdk.jmh",
							ArtifactID: "jmh-core",
							Scope:      "test",
						},
					},
				},
				{
					Name:         "jmh-generator-annprocess",
					Version:      "1.35",
					PURL:         "pkg:maven/org.openjdk.jmh/jmh-generator-annprocess@1.35",
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PomProperties: &pkg.PomProperties{
							GroupID:    "org.openjdk.jmh",
							ArtifactID: "jmh-generator-annprocess",
							Scope:      "test",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			for i := range test.expected {
				test.expected[i].Locations.Add(file.NewLocation(test.input))
			}
			pkgtest.TestFileParser(t, test.input, parserPomXML, test.expected, nil)
		})
	}
}

func Test_parsePomXMLProject(t *testing.T) {
	// TODO: ideally we would have the path to the contained pom.xml, not the jar
	jarLocation := file.NewLocation("path/to/archive.jar")
	tests := []struct {
		name     string
		expected parsedPomProject
	}{
		{
			name: "go case",
			expected: parsedPomProject{
				PomProject: &pkg.PomProject{
					Path: "test-fixtures/pom/commons-codec.pom.xml",
					Parent: &pkg.PomParent{
						GroupID:    "org.apache.commons",
						ArtifactID: "commons-parent",
						Version:    "42",
					},
					GroupID:     "commons-codec",
					ArtifactID:  "commons-codec",
					Version:     "1.11",
					Name:        "Apache Commons Codec",
					Description: "The Apache Commons Codec package contains simple encoder and decoders for various formats such as Base64 and Hexadecimal.  In addition to these widely used encoders and decoders, the codec package also maintains a collection of phonetic encoding utilities.",
					URL:         "http://commons.apache.org/proper/commons-codec/",
				},
			},
		},
		{
			name: "with license data",
			expected: parsedPomProject{
				PomProject: &pkg.PomProject{
					Path: "test-fixtures/pom/neo4j-license-maven-plugin.pom.xml",
					Parent: &pkg.PomParent{
						GroupID:    "org.sonatype.oss",
						ArtifactID: "oss-parent",
						Version:    "7",
					},
					GroupID:     "org.neo4j.build.plugins",
					ArtifactID:  "license-maven-plugin",
					Version:     "4-SNAPSHOT",
					Name:        "${project.artifactId}", // TODO: this is not an ideal answer
					Description: "Maven 2 plugin to check and update license headers in source files",
					URL:         "http://components.neo4j.org/${project.artifactId}/${project.version}", // TODO: this is not an ideal answer
				},
				Licenses: []pkg.License{
					{
						Value:          "The Apache Software License, Version 2.0",
						SPDXExpression: "", // TODO: ideally we would parse this title to get Apache-2.0 (created issue #2210 https://github.com/anchore/syft/issues/2210)
						Type:           license.Declared,
						URLs:           internal.NewStringSet("http://www.apache.org/licenses/LICENSE-2.0.txt"),
						Locations:      file.NewLocationSet(jarLocation),
					},
					{
						Value:          "MIT",
						SPDXExpression: "MIT",
						Type:           license.Declared,
						URLs:           internal.NewStringSet(),
						Locations:      file.NewLocationSet(jarLocation),
					},
					{
						Type:      license.Declared,
						URLs:      internal.NewStringSet("https://opensource.org/license/unlicense/"),
						Locations: file.NewLocationSet(jarLocation),
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture, err := os.Open(test.expected.Path)
			assert.NoError(t, err)

			actual, err := parsePomXMLProject(fixture.Name(), fixture, jarLocation)
			assert.NoError(t, err)

			assert.Equal(t, &test.expected, actual)
		})
	}
}

func Test_pomParent(t *testing.T) {
	tests := []struct {
		name     string
		input    *gopom.Parent
		expected *pkg.PomParent
	}{
		{
			name: "only group ID",
			input: &gopom.Parent{
				GroupID: stringPointer("org.something"),
			},
			expected: &pkg.PomParent{
				GroupID: "org.something",
			},
		},
		{
			name: "only artifact ID",
			input: &gopom.Parent{
				ArtifactID: stringPointer("something"),
			},
			expected: &pkg.PomParent{
				ArtifactID: "something",
			},
		},
		{
			name: "only Version",
			input: &gopom.Parent{
				Version: stringPointer("something"),
			},
			expected: &pkg.PomParent{
				Version: "something",
			},
		},
		{
			name:     "nil",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty",
			input:    &gopom.Parent{},
			expected: nil,
		},
		{
			name: "unused field",
			input: &gopom.Parent{
				RelativePath: stringPointer("something"),
			},
			expected: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, pomParent(gopom.Project{}, test.input))
		})
	}
}

func Test_cleanDescription(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name: "indent + multiline",
			input: `        The Apache Commons Codec package contains simple encoder and decoders for
        various formats such as Base64 and Hexadecimal.  In addition to these
        widely used encoders and decoders, the codec package also maintains a
        collection of phonetic encoding utilities.`,
			expected: "The Apache Commons Codec package contains simple encoder and decoders for various formats such as Base64 and Hexadecimal.  In addition to these widely used encoders and decoders, the codec package also maintains a collection of phonetic encoding utilities.",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, cleanDescription(stringPointer(test.input)))
		})
	}
}

func Test_resolveProperty(t *testing.T) {
	tests := []struct {
		name     string
		property string
		pom      gopom.Project
		expected string
	}{
		{
			name:     "property",
			property: "${version.number}",
			pom: gopom.Project{
				Properties: &gopom.Properties{
					Entries: map[string]string{
						"version.number": "12.5.0",
					},
				},
			},
			expected: "12.5.0",
		},
		{
			name:     "groupId",
			property: "${project.groupId}",
			pom: gopom.Project{
				GroupID: stringPointer("org.some.group"),
			},
			expected: "org.some.group",
		},
		{
			name:     "parent groupId",
			property: "${project.parent.groupId}",
			pom: gopom.Project{
				Parent: &gopom.Parent{
					GroupID: stringPointer("org.some.parent"),
				},
			},
			expected: "org.some.parent",
		},
		{
			name:     "nil pointer halts search",
			property: "${project.parent.groupId}",
			pom: gopom.Project{
				Parent: nil,
			},
			expected: "${project.parent.groupId}",
		},
		{
			name:     "nil string pointer halts search",
			property: "${project.parent.groupId}",
			pom: gopom.Project{
				Parent: &gopom.Parent{
					GroupID: nil,
				},
			},
			expected: "${project.parent.groupId}",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolved := resolveProperty(test.pom, stringPointer(test.property), test.name)
			assert.Equal(t, test.expected, resolved)
		})
	}
}

func stringPointer(s string) *string {
	return &s
}

func Test_getUtf8Reader(t *testing.T) {
	tests := []struct {
		name     string
		contents string
	}{
		{
			name: "unknown encoding",
			// random binary contents
			contents: "BkiJz02JyEWE0nXR6TH///9NicpJweEETIucJIgAAABJicxPjQwhTY1JCE05WQh0BU2J0eunTYshTIusJIAAAAAPHwBNOeV1BUUx2+tWTIlUJDhMiUwkSEyJRCQgSIl8JFBMiQ==",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(tt.contents))

			got, err := getUtf8Reader(decoder)
			require.NoError(t, err)
			gotBytes, err := io.ReadAll(got)
			require.NoError(t, err)
			// if we couldn't decode the section as UTF-8, we should get a replacement character
			assert.Contains(t, string(gotBytes), "�")
		})
	}
}
