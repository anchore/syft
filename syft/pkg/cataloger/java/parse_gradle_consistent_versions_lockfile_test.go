package java

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
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
	contents := "# Run ./gradlew writeVersionsLocks to regenerate this file\norg.example:before:1.0 (1 constraints: 00000000)\n" + strings.Repeat("a", 2<<20) + "\norg.example:after:2.0 (1 constraints: 00000000)\n"
	reader := file.NewLocationReadCloser(file.NewLocation("versions.lock"), io.NopCloser(strings.NewReader(contents)))

	pkgs, _, err := parseGradleConsistentVersionsLockfile(context.Background(), nil, nil, reader)
	require.ErrorIs(t, err, bufio.ErrTooLong)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "before", pkgs[0].Name)
}

func Test_parseGradleConsistentVersionsLockfile_requiresLockfileEntrySignature(t *testing.T) {
	contents := strings.Join([]string{
		"# Run ./gradlew writeVersionsLocks to regenerate this file. Blank lines are to minimize merge conflicts.",
		"com.example:valid:1.0 (1 constraints: deadbeef)",
		"com.example:bare:2.0",
		"com.example:missing-count:3.0 (constraints: deadbeef)",
		"com.example:bad-hash:4.0 (1 constraints: not-a-hash)",
		"com.example:word-hash:4.5 (3 constraints: hash_word)",
		"[Test dependencies]",
		"[Unexpected section]",
		"com.example:test:5.0 (2 constraints: 0123abcd)",
	}, "\r\n")
	reader := file.NewLocationReadCloser(file.NewLocation("versions.lock"), io.NopCloser(strings.NewReader(contents)))

	pkgs, _, err := parseGradleConsistentVersionsLockfile(context.Background(), nil, nil, reader)
	require.NoError(t, err)
	require.Len(t, pkgs, 3)
	assert.Equal(t, "valid", pkgs[0].Name)
	assert.Equal(t, "word-hash", pkgs[1].Name)
	assert.Equal(t, "test", pkgs[2].Name)
	assert.Equal(t, "test", pkgs[2].Metadata.(pkg.JavaArchive).PomProperties.Scope)
}

func Test_parseGradleConsistentVersionsLockfile_acceptsGradleHeaders(t *testing.T) {
	tests := []string{
		"# Run ./gradlew --write-locks to regenerate this file",
		"# Run ./gradlew writeVersionsLock to regenerate this file",
		"# Run ./gradlew writeVersionsLocks to regenerate this file",
		"# Run ./gradlew writeVersionsLocks to regenerate this file. Blank lines are to minimize merge conflicts.",
		"# Run ./gradlew :writeVersionsLocks to regenerate this file",
		"# Run ./gradlew --project-dir project writeVersionsLocks to regenerate this file",
		"# Run gradlew.bat writeVersionsLocks to regenerate this file",
	}

	for _, header := range tests {
		t.Run(header, func(t *testing.T) {
			contents := header + "\r\norg.example:valid:1.0 (1 constraints: deadbeef)\r\n"
			reader := file.NewLocationReadCloser(file.NewLocation("versions.lock"), io.NopCloser(strings.NewReader(contents)))

			pkgs, _, err := parseGradleConsistentVersionsLockfile(context.Background(), nil, nil, reader)
			require.NoError(t, err)
			require.Len(t, pkgs, 1)
			assert.Equal(t, "valid", pkgs[0].Name)
		})
	}
}

func Test_parseGradleConsistentVersionsLockfile_rejectsUnidentifiedVersionsLock(t *testing.T) {
	for _, header := range []string{
		"",
		"# Generated dependency versions",
		"Run ./gradlew writeVersionsLocks to regenerate this file",
		"org.example:gradlew:1.0 (1 constraints: deadbeef)",
	} {
		t.Run(header, func(t *testing.T) {
			contents := header + "\r\norg.example:valid:1.0 (1 constraints: deadbeef)\r\n"
			reader := file.NewLocationReadCloser(file.NewLocation("versions.lock"), io.NopCloser(strings.NewReader(contents)))

			pkgs, _, err := parseGradleConsistentVersionsLockfile(context.Background(), nil, nil, reader)
			require.NoError(t, err)
			assert.Empty(t, pkgs)
		})
	}
}

func TestNewGradleLockfileCataloger_ignoresUnidentifiedVersionsLock(t *testing.T) {
	dir := t.TempDir()
	contents := "org.example:valid:1.0 (1 constraints: deadbeef)\r\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "versions.lock"), []byte(contents), 0o600))

	pkgtest.NewCatalogTester().
		FromDirectory(t, dir).
		Expects(nil, nil).
		TestCataloger(t, NewGradleLockfileCataloger())
}
