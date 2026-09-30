package internal

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/anchore/syft/syft/source/stereoscopesource"
)

func Test_allRegularFiles(t *testing.T) {
	tests := []struct {
		name            string
		setup           func() file.Resolver
		wantRealPaths   *strset.Set
		wantAccessPaths *strset.Set
	}{
		{
			name: "image",
			setup: func() file.Resolver {
				testImage := "image-file-type-mix"

				img := imagetest.GetFixtureImage(t, "docker-archive", testImage)

				s := stereoscopesource.New(img, stereoscopesource.ImageConfig{
					Reference: testImage,
				})

				r, err := s.FileResolver(source.SquashedScope)
				require.NoError(t, err)

				return r
			},
			wantRealPaths:   strset.New("/file-1.txt"),
			wantAccessPaths: strset.New("/file-1.txt", "/symlink-1", "/hardlink-1"),
		},
		{
			name: "directory",
			setup: func() file.Resolver {
				s, err := directorysource.NewFromPath("testdata/symlinked-root/nested/link-root")
				require.NoError(t, err)
				r, err := s.FileResolver(source.SquashedScope)
				require.NoError(t, err)
				return r
			},
			wantRealPaths:   strset.New("file1.txt", "nested/file2.txt"),
			wantAccessPaths: strset.New("file1.txt", "nested/file2.txt", "nested/linked-file1.txt"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := tt.setup()
			locations := AllRegularFiles(context.Background(), resolver)
			realLocations := strset.New()
			virtualLocations := strset.New()
			for _, l := range locations {
				realLocations.Add(l.RealPath)
				if l.AccessPath != "" {
					virtualLocations.Add(l.AccessPath)
				}
			}

			// this is difficult to reproduce in a cross-platform way
			realLocations.Remove("/hardlink-1")
			virtualLocations.Remove("/hardlink-1")
			tt.wantRealPaths.Remove("/hardlink-1")
			tt.wantAccessPaths.Remove("/hardlink-1")

			assert.ElementsMatch(t, tt.wantRealPaths.List(), realLocations.List(), "real paths differ: "+cmp.Diff(tt.wantRealPaths.List(), realLocations.List()))
			assert.ElementsMatch(t, tt.wantAccessPaths.List(), virtualLocations.List(), "virtual paths differ: "+cmp.Diff(tt.wantAccessPaths.List(), virtualLocations.List()))
		})
	}
}

// Test_allRegularFiles_directoryScan covers a plain directory on the host filesystem, which is the shape that
// the file digest cataloger silently produced nothing for: AllRegularFiles resolves each location it is handed
// by path, so a resolver that cannot resolve the paths it reports returns no files at all.
//
// see anchore/syft#4564
func Test_allRegularFiles_directoryScan(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "file1.txt"), []byte("file 1"), 0600))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "sub"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "sub", "file2.txt"), []byte("file 2"), 0600))

	s, err := directorysource.NewFromPath(root)
	require.NoError(t, err)

	resolver, err := s.FileResolver(source.SquashedScope)
	require.NoError(t, err)

	var realPaths []string
	for _, l := range AllRegularFiles(context.Background(), resolver) {
		// paths are relative to the resolver root, and whether they are rooted depends on the base path
		realPaths = append(realPaths, "/"+strings.TrimPrefix(filepath.ToSlash(l.RealPath), "/"))
	}

	assert.ElementsMatch(t, []string{"/file1.txt", "/sub/file2.txt"}, realPaths)
}
