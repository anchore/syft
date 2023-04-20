package java

import (
	"github.com/anchore/syft/syft/file"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_parserGradleLockfile(t *testing.T) {
	tests := []struct {
		input    string
		expected []pkg.Package
	}{
		{
			input: "test-fixtures/gradle/gradle.lockfile",
			expected: []pkg.Package{
				{
					Name:         "hamcrest-core",
					Version:      "1.3",
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
				},
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
				test.expected[i].Locations.Add(file.NewLocation(test.input))
			}
			pkgtest.TestFileParser(t, test.input, parseGradleLockfile, test.expected, nil)
		})
	}
}
