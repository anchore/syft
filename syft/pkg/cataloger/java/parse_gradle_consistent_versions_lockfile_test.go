package java

import (
	"bufio"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
				{
					Name:     "junit",
					Version:  "4.13.2",
					Language: pkg.Java,
					Type:     pkg.JavaPkg,
					PURL:     "pkg:maven/junit/junit@4.13.2",
					Metadata: pkg.JavaArchive{
						PomProject:    &pkg.JavaPomProject{GroupID: "junit", ArtifactID: "junit", Version: "4.13.2", Name: "junit"},
						PomProperties: &pkg.JavaPomProperties{GroupID: "junit", ArtifactID: "junit", Version: "4.13.2", Scope: "test"},
					},
				},
				{
					Name:     "hamcrest-core",
					Version:  "1.3",
					Language: pkg.Java,
					Type:     pkg.JavaPkg,
					PURL:     "pkg:maven/org.hamcrest/hamcrest-core@1.3",
					Metadata: pkg.JavaArchive{
						PomProject:    &pkg.JavaPomProject{GroupID: "org.hamcrest", ArtifactID: "hamcrest-core", Version: "1.3", Name: "hamcrest-core"},
						PomProperties: &pkg.JavaPomProperties{GroupID: "org.hamcrest", ArtifactID: "hamcrest-core", Version: "1.3", Scope: "test"},
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

func Test_parseGradleConsistentVersionsLockfile_lineTooLong(t *testing.T) {
	// packages before an oversized line are kept, and the scan error is still reported
	contents := "org.example:before:1.0 (1 constraints: 00000000)\n" + strings.Repeat("a", 2<<20) + "\norg.example:after:2.0 (1 constraints: 00000000)\n"
	reader := file.NewLocationReadCloser(file.NewLocation("versions.lock"), io.NopCloser(strings.NewReader(contents)))

	pkgs, _, err := parseGradleConsistentVersionsLockfile(context.Background(), nil, nil, reader)
	require.ErrorIs(t, err, bufio.ErrTooLong)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "before", pkgs[0].Name)
}
