package java

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
)

func Test_parserGradle(t *testing.T) {
	tests := []struct {
		input    string
		expected []pkg.Package
	}{
		{
			input: "test-fixtures/gradle/build.gradle",
			expected: []pkg.Package{
				{
					Name:         "joda-time",
					Version:      "2.2",
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
				},
				{
					Name:         "junit",
					Version:      "4.12",
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			for i := range test.expected {
				test.expected[i].Locations.Add(source.NewLocation(test.input))
			}
			pkgtest.TestFileParser(t, test.input, parserBuildGradle, test.expected, nil)
		})
	}
}
