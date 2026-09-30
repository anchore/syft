package fileresolver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
)

// note: this file deliberately carries no build constraint. The rest of the directory resolver tests are
// //go:build !windows, which is how the path handling this covers was able to break on Windows unnoticed.

// Test_Directory_ResolvesItsOwnPaths asserts that every path the resolver reports can be handed straight back to
// the resolver. Cataloging depends on that round trip: AllRegularFiles(), and with it the file digest cataloger,
// takes the locations from AllLocations() and resolves each one by path.
func Test_Directory_ResolvesItsOwnPaths(t *testing.T) {
	tests := []struct {
		name string
		base func(root string) string
	}{
		{
			// the CLI defaults the base path to the directory being scanned
			name: "base is the scan root",
			base: func(root string) string { return root },
		},
		{
			// directorysource.NewFromPath leaves the base unset
			name: "no base",
			base: func(string) string { return "" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(root, "file1.txt"), []byte("file 1"), 0600))
			require.NoError(t, os.MkdirAll(filepath.Join(root, "sub"), 0700))
			require.NoError(t, os.WriteFile(filepath.Join(root, "sub", "file2.txt"), []byte("file 2"), 0600))

			resolver, err := NewFromDirectory(root, tt.base(root))
			require.NoError(t, err)

			var resolved []string
			for location := range resolver.AllLocations(context.Background()) {
				metadata, err := resolver.FileMetadataByLocation(location)
				require.NoError(t, err)

				if metadata.Type != stereoscopeFile.TypeRegular {
					continue
				}

				locations, err := resolver.FilesByPath(location.RealPath)
				require.NoError(t, err)
				require.Lenf(t, locations, 1, "resolver could not resolve a path it reported itself: %q", location.RealPath)

				assert.Truef(t, resolver.HasPath(location.RealPath), "resolver does not have a path it reported itself: %q", location.RealPath)

				resolved = append(resolved, filepath.ToSlash(locations[0].RealPath))
			}

			// paths are relative to the resolver root, and whether they are rooted depends on the base path
			for i, p := range resolved {
				resolved[i] = "/" + strings.TrimPrefix(p, "/")
			}

			assert.ElementsMatch(t, []string{"/file1.txt", "/sub/file2.txt"}, resolved)
		})
	}
}
