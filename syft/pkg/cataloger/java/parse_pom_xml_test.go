package java

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vifraa/gopom"

	"github.com/anchore/syft/syft/pkg"
)

func Test_parserPomXML(t *testing.T) {
	tests := []struct {
		input    string
		expected []*pkg.Package
	}{
		{
			input: "test-fixtures/pom/pom.xml",
			expected: []*pkg.Package{
				{
					Name:         "joda-time",
					Version:      "2.9.2",
					FoundBy:      javaPomCataloger,
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PURL: "pkg:maven/com.joda/joda-time@2.9.2",
					},
				},
				{
					Name:         "junit",
					Version:      "4.12",
					FoundBy:      "java-pom-cataloger",
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PURL: "pkg:maven/junit/junit@4.12",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			fixture, err := os.Open(test.input)
			assert.NoError(t, err)

			actual, relationships, err := parserPomXML(fixture.Name(), fixture)
			assert.NoError(t, err)
			assert.Nil(t, relationships)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func Test_parseCommonsTextPomXMLProject(t *testing.T) {
	tests := []struct {
		input    string
		expected []*pkg.Package
	}{
		{
			input: "test-fixtures/pom/commons-text.pom.xml",
			expected: []*pkg.Package{
				{
					Name:         "commons-lang3",
					Version:      "3.12.0",
					FoundBy:      javaPomCataloger,
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PURL: "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
					},
				},
				{
					Name:         "junit-jupiter",
					Version:      "",
					FoundBy:      javaPomCataloger,
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PURL: "pkg:maven/org.junit.jupiter/junit-jupiter",
					},
				},
				{
					Name:         "assertj-core",
					Version:      "3.23.1",
					FoundBy:      javaPomCataloger,
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PURL: "pkg:maven/org.assertj/assertj-core@3.23.1",
					},
				},
				{
					Name:         "commons-io",
					Version:      "2.11.0",
					FoundBy:      javaPomCataloger,
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PURL: "pkg:maven/commons-io/commons-io@2.11.0",
					},
				},
				{
					Name:         "mockito-inline",
					Version:      "4.8.0",
					FoundBy:      javaPomCataloger,
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PURL: "pkg:maven/org.mockito/mockito-inline@4.8.0",
					},
				},
				{
					Name:         "js",
					Version:      "22.0.0.2",
					FoundBy:      javaPomCataloger,
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PURL: "pkg:maven/org.graalvm.js/js@22.0.0.2",
					},
				},
				{
					Name:         "js-scriptengine",
					Version:      "22.0.0.2",
					FoundBy:      javaPomCataloger,
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PURL: "pkg:maven/org.graalvm.js/js-scriptengine@22.0.0.2",
					},
				},
				{
					Name:         "commons-rng-simple",
					Version:      "1.4",
					FoundBy:      javaPomCataloger,
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PURL: "pkg:maven/org.apache.commons/commons-rng-simple@1.4",
					},
				},
				{
					Name:         "jmh-core",
					Version:      "1.35",
					FoundBy:      javaPomCataloger,
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PURL: "pkg:maven/org.openjdk.jmh/jmh-core@1.35",
					},
				},
				{
					Name:         "jmh-generator-annprocess",
					Version:      "1.35",
					FoundBy:      javaPomCataloger,
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PURL: "pkg:maven/org.openjdk.jmh/jmh-generator-annprocess@1.35",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			fixture, err := os.Open(test.input)
			assert.NoError(t, err)

			actual, relationships, err := parserPomXML(fixture.Name(), fixture)
			assert.NoError(t, err)
			assert.Nil(t, relationships)
			assert.Equal(t, test.expected, actual)
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
			assert.Equal(t, test.expected, pomParent(test.input))
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
