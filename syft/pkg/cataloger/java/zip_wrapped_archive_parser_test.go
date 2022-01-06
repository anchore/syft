package java

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parseZipWrappedJavaArchive(t *testing.T) {
	tests := []struct {
		fixture  string
		expected []string
	}{
		{
			fixture: "test-fixtures/java-builds/packages/example-java-app-maven-0.1.0.zip",
			expected: []string{
				"example-java-app-maven",
				"joda-time",
			},
		},
	}
	for _, test := range tests {
		t.Run(path.Base(test.fixture), func(t *testing.T) {
			generateJavaBuildFixture(t, test.fixture)

			fixture, err := os.Open(test.fixture)
			if err != nil {
				t.Fatalf("failed to open fixture: %+v", err)
			}

			actualPkgs, _, err := parseZipWrappedJavaArchive(test.fixture, fixture)
			require.NoError(t, err)

			var actualNames []string
			for _, p := range actualPkgs {
				actualNames = append(actualNames, p.Name)
			}

			assert.ElementsMatch(t, test.expected, actualNames)
		})
	}
}
