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
		{
			image: "image-java-zulu-8",
			expected: []string{
				"zulu @ 1.8.0_462-b08 (/usr/lib/jvm/zulu8-ca-amd64/bin/jdb)",
			},
		},
		{
			image: "image-java-zulu-21",
			expected: []string{
				"zulu @ 21.0.8+9-LTS (/usr/lib/jvm/zulu21-ca-amd64/bin/java)",
			},
		},
		{
			image: "image-java-ibm-8",
			expected: []string{
				"java @ 1.8.0-foreman_2023_10_12_13_27-b00 (/opt/ibm/java/jre/bin/java)",
			},
		},
		{
			image: "image-java-ibm-jre-8",
			expected: []string{
				"java @ 1.8.0-_2025_04_14_02_37-b00 (/opt/ibm/java/jre/bin/java)",
			},
		},
		{
			image: "image-java-ibm-sdk-8",
			expected: []string{
				"java_sdk @ 1.8.0-foreman_2022_01_20_09_33-b00 (/opt/ibm/java/bin/jdb)",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			c := NewClassifierCataloger(ClassifierCatalogerConfig{
				Classifiers: defaultJavaClassifiers(),
			})
			pkgtest.NewCatalogTester().
				WithImageResolver(t, tt.image).
				ExpectsPackageStrings(tt.expected).
				TestCataloger(t, c)
		})
	}
}
