package java

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func TestParseJavaPomProperties(t *testing.T) {
	tests := []struct {
		expected pkg.JavaPomProperties
	}{
		{
			expected: pkg.JavaPomProperties{
				Path:       "test-fixtures/pom/small.pom.properties",
				GroupID:    "org.anchore",
				ArtifactID: "example-java-app-maven",
				Version:    "0.1.0",
			},
		},
		{
			expected: pkg.JavaPomProperties{
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
		{
			expected: pkg.JavaPomProperties{
				Path:       "test-fixtures/pom/colon-delimited.pom.properties",
				GroupID:    "org.anchore",
				ArtifactID: "example-java-app-maven",
				Version:    "0.1.0",
			},
		},
		{
			expected: pkg.JavaPomProperties{
				Path:       "test-fixtures/pom/equals-delimited-with-colons.pom.properties",
				GroupID:    "org.anchore",
				ArtifactID: "example-java:app-maven",
				Version:    "0.1.0:something",
			},
		},
		{
			expected: pkg.JavaPomProperties{
				Path:       "test-fixtures/pom/colon-delimited-with-equals.pom.properties",
				GroupID:    "org.anchore",
				ArtifactID: "example-java=app-maven",
				Version:    "0.1.0=something",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.expected.Path, func(t *testing.T) {
			fixture, err := os.Open(test.expected.Path)
			assert.NoError(t, err)

			actual, err := parsePomProperties(fixture.Name(), fixture)
			assert.NoError(t, err)

			assert.Equal(t, &test.expected, actual)
		})
	}
}
