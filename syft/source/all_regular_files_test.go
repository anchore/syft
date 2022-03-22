package source

import (
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_allRegularFiles(t *testing.T) {
	type access struct {
		realPath    string
		virtualPath string
	}
	tests := []struct {
		name             string
		setup            func() FileResolver
		wantRealPaths    *strset.Set
		wantVirtualPaths *strset.Set
	}{
		{
			name: "image",
			setup: func() FileResolver {
				img := imagetest.GetFixtureImage(t, "docker-archive", "image-file-type-mix")

				s, err := NewFromImage(img, "---")
				require.NoError(t, err)

				r, err := s.FileResolver(SquashedScope)
				require.NoError(t, err)

				return r
			},
			wantRealPaths:    strset.New("/file-1.txt"),
			wantVirtualPaths: strset.New("/file-1.txt", "/symlink-1", "/hardlink-1"),
		},
		{
			name: "directory",
			setup: func() FileResolver {
				s, err := NewFromDirectory("test-fixtures/symlinked-root/nested/link-root")
				require.NoError(t, err)
				r, err := s.FileResolver(SquashedScope)
				require.NoError(t, err)
				return r
			},
			wantRealPaths:    strset.New("file1.txt", "nested/file2.txt"),
			wantVirtualPaths: strset.New("nested/linked-file1.txt"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := tt.setup()
			locations := AllRegularFiles(resolver)
			realLocations := strset.New()
			virtualLocations := strset.New()
			for _, l := range locations {
				realLocations.Add(l.RealPath)
				if l.VirtualPath != "" {
					virtualLocations.Add(l.VirtualPath)
				}
			}
			assert.ElementsMatch(t, tt.wantRealPaths.List(), realLocations.List(), "mismatched real paths")
			assert.ElementsMatch(t, tt.wantVirtualPaths.List(), virtualLocations.List(), "mismatched virtual paths")
		})
	}
}
