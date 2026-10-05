package java

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func readManifest(t *testing.T, ctx context.Context, parser *archiveParser) *pkg.JavaManifest {
	t.Helper()

	matches := parser.fileManifest.GlobMatch(false, manifestGlob)
	require.Len(t, matches, 1)

	contents, err := intFile.ContentsFromZip(ctx, parser.archivePath, matches...)
	require.NoError(t, err)

	manifest, err := parseJavaManifest(parser.archivePath, strings.NewReader(contents[matches[0]]))
	require.NoError(t, err)

	return manifest
}

func Test_archiveParser_versionFromPropertiesFile(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		want    string
	}{
		{
			// "tag=v0.63.5"
			name:    "release tag from root version.properties",
			fixture: "uber-app-version-properties",
			want:    "0.63.5",
		},
		{
			// clickhouse-jdbc ships "version=${revision}" must not become a version
			name:    "unresolved build placeholder is rejected",
			fixture: "uber-app-version-placeholder",
			want:    "",
		},
		{
			// no Main-Class -> cant tell app uberjar from bundled dep
			name:    "library without Main-Class is rejected",
			fixture: "lib-with-version-properties",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := pkgtest.Context(t)

			fixturePath := generateJavaMetadataJarFixture(t, tt.fixture, "jar")
			fixture, err := os.Open(fixturePath)
			require.NoError(t, err)

			parser, cleanupFn, err := newJavaArchiveParser(ctx,
				file.LocationReadCloser{
					Location:   file.NewLocation(fixture.Name()),
					ReadCloser: fixture,
				}, false, DefaultArchiveCatalogerConfig())
			defer cleanupFn()
			require.NoError(t, err)

			assert.Equal(t, tt.want, parser.versionFromPropertiesFile(ctx, readManifest(t, ctx, parser)))
		})
	}
}

func Test_archiveParser_versionFromPropertiesFile_noManifest(t *testing.T) {
	ctx := pkgtest.Context(t)

	fixturePath := generateJavaMetadataJarFixture(t, "uber-app-version-properties", "jar")
	fixture, err := os.Open(fixturePath)
	require.NoError(t, err)

	parser, cleanupFn, err := newJavaArchiveParser(ctx,
		file.LocationReadCloser{
			Location:   file.NewLocation(fixture.Name()),
			ReadCloser: fixture,
		}, false, DefaultArchiveCatalogerConfig())
	defer cleanupFn()
	require.NoError(t, err)

	assert.Empty(t, parser.versionFromPropertiesFile(ctx, nil))
}

func Test_releaseVersionPattern(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{"v0.63.5", "0.63.5"},
		{"0.63.5", "0.63.5"},
		{"2.5.1", "2.5.1"},
		{"1.0.0-SNAPSHOT", "1.0.0-SNAPSHOT"},
		{"3", "3"},
		{"${revision}", ""},
		{"trunk-nightly build", ""},
		{"valhalla", ""},
		{"", ""},
		{"v", ""},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			var got string
			if m := releaseVersionPattern.FindStringSubmatch(tt.value); m != nil {
				got = m[1]
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
