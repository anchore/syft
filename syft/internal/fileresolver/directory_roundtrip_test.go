package fileresolver

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
)

// a location handed out by the resolver should be resolvable again by its own path. This is what the file
// digest cataloger relies on, and it silently found nothing on windows (see #5325).
func TestDirectory_LocationPathsRoundTrip(t *testing.T) {
	// resolve symlinks up front (e.g. /var -> /private/var on macOS) so the cwd prefix matches the indexed paths
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "sub", "dir"), 0o755))
	for _, p := range []string{"top.txt", filepath.Join("sub", "mid.txt"), filepath.Join("sub", "dir", "deep.txt")} {
		require.NoError(t, os.WriteFile(filepath.Join(root, p), []byte(p), 0o600))
	}

	// mirror `syft dir:.` from within the scanned directory
	t.Chdir(root)

	resolver, err := NewFromDirectory(".", "")
	require.NoError(t, err)

	var regular int
	for loc := range resolver.AllLocations(context.Background()) {
		md, err := resolver.FileMetadataByLocation(loc)
		require.NoError(t, err)
		if md.Type != stereoscopeFile.TypeRegular {
			continue
		}
		regular++

		assert.NotContains(t, loc.RealPath, `\`, "location paths should be posix")

		found, err := resolver.FilesByPath(loc.RealPath)
		require.NoError(t, err)
		assert.Len(t, found, 1, "unable to resolve %q by its own path", loc.RealPath)
	}
	assert.Equal(t, 3, regular)
}
