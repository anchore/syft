package java

import (
	"context"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
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

			gzp := newGenericZipWrappedJavaArchiveParser(ArchiveCatalogerConfig{})

			actualPkgs, _, err := gzp.parseZipWrappedJavaArchive(context.Background(), nil, nil, file.LocationReadCloser{
				Location:   file.NewLocation(test.fixture),
				ReadCloser: fixture,
			})
			require.NoError(t, err)

			var actualNames []string
			for _, p := range actualPkgs {
				actualNames = append(actualNames, p.Name)
			}

			assert.ElementsMatch(t, test.expected, actualNames)
		})
	}
}
