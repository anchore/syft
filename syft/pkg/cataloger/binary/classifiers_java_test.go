package binary

import (
	"testing"

	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_JavaBinaryImage(t *testing.T) {
	tests := []struct {
		image    string
		expected []string
	}{
		{
			image: "image-java-binary",
			expected: []string{
				"java @ 1.8.0-foreman_2022_09_22_15_30-b00 (/staged/positive/ibm/java)",
				"jre @ 19.0.1+10-21 (/staged/positive/oracle-macos/java)",
				"openjdk @ 1.8.0_352-b08 (/staged/positive/openjdk/java)",
				"openjdk @ 11.0.17+8-LTS (/staged/positive/openjdk-lts/java)",
			},
		},
	}

	for _, tt := range tests {
		c := NewClassifierCataloger(ClassifierCatalogerConfig{
			Classifiers: defaultJavaClassifiers(),
		})
		pkgtest.NewCatalogTester().
			WithImageResolver(t, tt.image).
			ExpectsPackageStrings(tt.expected).
			TestCataloger(t, c)
	}
}
