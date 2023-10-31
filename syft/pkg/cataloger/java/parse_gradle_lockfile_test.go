package java

import (
	"testing"

	"github.com/anchore/syft/syft/file"
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
					Name:     "commons-text",
					Version:  "1.8",
					Language: pkg.Java,
					Type:     pkg.JavaPkg,
					PURL:     "pkg:maven/org.apache.commons/commons-text@1.8",
					Metadata: pkg.JavaArchive{
						PomProject: &pkg.JavaPomProject{GroupID: "org.apache.commons", ArtifactID: "commons-text", Version: "1.8", Name: "commons-text"},
					},
				},
				{
					Name:     "hamcrest-core",
					Version:  "1.3",
					Language: pkg.Java,
					Type:     pkg.JavaPkg,
					PURL:     "pkg:maven/org.hamcrest/hamcrest-core@1.3",
					Metadata: pkg.JavaArchive{
						PomProject: &pkg.JavaPomProject{GroupID: "org.hamcrest", ArtifactID: "hamcrest-core", Version: "1.3", Name: "hamcrest-core"},
					},
				},
				{
					Name:     "joda-time",
					Version:  "2.2",
					Language: pkg.Java,
					Type:     pkg.JavaPkg,
					PURL:     "pkg:maven/joda-time/joda-time@2.2",
					Metadata: pkg.JavaArchive{
						PomProject: &pkg.JavaPomProject{GroupID: "joda-time", ArtifactID: "joda-time", Version: "2.2", Name: "joda-time"},
					},
				},
				{
					Name:     "junit",
					Version:  "4.12",
					Language: pkg.Java,
					Type:     pkg.JavaPkg,
					PURL:     "pkg:maven/junit/junit@4.12",
					Metadata: pkg.JavaArchive{
						PomProject: &pkg.JavaPomProject{GroupID: "junit", ArtifactID: "junit", Version: "4.12", Name: "junit"},
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
			pkgtest.TestFileParser(t, test.input, parseGradleLockfile, test.expected, nil)
		})
	}
}
