package java

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_parseGradleConsistentVersionsLockfile(t *testing.T) {
	tests := []struct {
		input    string
		expected []pkg.Package
	}{
		{
			input: "testdata/gradle-consistent-versions/versions.lock",
			expected: []pkg.Package{
				{
					Name:     "jackson-annotations",
					Version:  "2.12.3",
					Language: pkg.Java,
					Type:     pkg.JavaPkg,
					PURL:     "pkg:maven/com.fasterxml.jackson.core/jackson-annotations@2.12.3",
					Metadata: pkg.JavaArchive{
						PomProject: &pkg.JavaPomProject{GroupID: "com.fasterxml.jackson.core", ArtifactID: "jackson-annotations", Version: "2.12.3", Name: "jackson-annotations"},
					},
				},
				{
					Name:     "guava",
					Version:  "30.1.1-jre",
					Language: pkg.Java,
					Type:     pkg.JavaPkg,
					PURL:     "pkg:maven/com.google.guava/guava@30.1.1-jre",
					Metadata: pkg.JavaArchive{
						PomProject: &pkg.JavaPomProject{GroupID: "com.google.guava", ArtifactID: "guava", Version: "30.1.1-jre", Name: "guava"},
					},
				},
				{
					Name:     "okhttp",
					Version:  "3.12.0",
					Language: pkg.Java,
					Type:     pkg.JavaPkg,
					PURL:     "pkg:maven/com.squareup.okhttp3/okhttp@3.12.0",
					Metadata: pkg.JavaArchive{
						PomProject: &pkg.JavaPomProject{GroupID: "com.squareup.okhttp3", ArtifactID: "okhttp", Version: "3.12.0", Name: "okhttp"},
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
			pkgtest.TestFileParser(t, test.input, parseGradleConsistentVersionsLockfile, test.expected, nil)
		})
	}
}
