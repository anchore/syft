package java

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vifraa/gopom"

	"github.com/anchore/syft/syft/file"
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
						PomProperties: &pkg.PomProperties{GroupID: "com.joda"},
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
						PomProperties: &pkg.PomProperties{GroupID: "junit"},
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
						PomProperties: &pkg.PomProperties{GroupID: "org.apache.commons"},
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
						PomProperties: &pkg.PomProperties{GroupID: "org.junit.jupiter"},
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
						PomProperties: &pkg.PomProperties{GroupID: "org.assertj"},
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
						PomProperties: &pkg.PomProperties{GroupID: "commons-io"},
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
						PomProperties: &pkg.PomProperties{GroupID: "org.mockito"},
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
						PomProperties: &pkg.PomProperties{GroupID: "org.graalvm.js"},
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
						PomProperties: &pkg.PomProperties{GroupID: "org.graalvm.js"},
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
						PomProperties: &pkg.PomProperties{GroupID: "org.apache.commons"},
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
						PomProperties: &pkg.PomProperties{GroupID: "org.openjdk.jmh"},
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
						PomProperties: &pkg.PomProperties{GroupID: "org.openjdk.jmh"},
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
	tests := []struct {
		expected pkg.PomProject
	}{
		{
			expected: pkg.PomProject{
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
	}

	for _, test := range tests {
		t.Run(test.expected.Path, func(t *testing.T) {
			fixture, err := os.Open(test.expected.Path)
			assert.NoError(t, err)

			actual, err := parsePomXMLProject(fixture.Name(), fixture)
			assert.NoError(t, err)

			assert.Equal(t, &test.expected, actual)
		})
	}
}

func Test_pomParent(t *testing.T) {
	tests := []struct {
		name     string
		input    gopom.Parent
		expected *pkg.PomParent
	}{
		{
			name: "only group ID",
			input: gopom.Parent{
				GroupID: "org.something",
			},
			expected: &pkg.PomParent{
				GroupID: "org.something",
			},
		},
		{
			name: "only artifact ID",
			input: gopom.Parent{
				ArtifactID: "something",
			},
			expected: &pkg.PomParent{
				ArtifactID: "something",
			},
		},
		{
			name: "only Version",
			input: gopom.Parent{
				Version: "something",
			},
			expected: &pkg.PomParent{
				Version: "something",
			},
		},
		{
			name:     "empty",
			input:    gopom.Parent{},
			expected: nil,
		},
		{
			name: "unused field",
			input: gopom.Parent{
				RelativePath: "something",
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
			assert.Equal(t, test.expected, cleanDescription(test.input))
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
				Properties: gopom.Properties{
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
				GroupID: "org.some.group",
			},
			expected: "org.some.group",
		},
		{
			name:     "parent groupId",
			property: "${project.parent.groupId}",
			pom: gopom.Project{
				Parent: gopom.Parent{
					GroupID: "org.some.parent",
				},
			},
			expected: "org.some.parent",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolved := resolveProperty(test.pom, test.property)
			assert.Equal(t, test.expected, resolved)
		})
	}
}
