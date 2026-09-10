//go:build !windows

package fileresolver

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

// Test_DirectoryResolver_stampsFileSystemID verifies that a resolver built with a non-empty
// fileSystemID stamps it onto the Coordinates of every Location returned across all access paths.
// This is the identity mechanism that keeps identically-named files in different extracted
// archives from colliding in the coordinate-keyed SBOM tables.
func Test_DirectoryResolver_stampsFileSystemID(t *testing.T) {
	const fsID = "some/path/to.zip/some/nested/path.tar.gz"

	resolver, err := NewFromDirectoryWithFS("./testdata/image-symlinks", "", fsID)
	require.NoError(t, err)

	t.Run("FilesByPath", func(t *testing.T) {
		locations, err := resolver.FilesByPath("/file-1.txt")
		require.NoError(t, err)
		require.NotEmpty(t, locations)
		for _, l := range locations {
			assert.Equal(t, fsID, l.FileSystemID, "FilesByPath did not stamp FileSystemID")
		}
	})

	t.Run("FilesByGlob", func(t *testing.T) {
		locations, err := resolver.FilesByGlob("**/*.txt")
		require.NoError(t, err)
		require.NotEmpty(t, locations)
		for _, l := range locations {
			assert.Equal(t, fsID, l.FileSystemID, "FilesByGlob did not stamp FileSystemID")
		}
	})

	t.Run("FilesByMIMEType", func(t *testing.T) {
		locations, err := resolver.FilesByMIMEType("text/plain")
		require.NoError(t, err)
		require.NotEmpty(t, locations)
		for _, l := range locations {
			assert.Equal(t, fsID, l.FileSystemID, "FilesByMIMEType did not stamp FileSystemID")
		}
	})

	t.Run("AllLocations", func(t *testing.T) {
		var count int
		for l := range resolver.AllLocations(context.Background()) {
			assert.Equal(t, fsID, l.FileSystemID, "AllLocations did not stamp FileSystemID")
			count++
		}
		require.NotZero(t, count)
	})
}

// Test_DirectoryResolver_emptyFileSystemID confirms that an ordinary directory scan (via the
// unchanged NewFromDirectory) continues to produce empty FileSystemIDs.
func Test_DirectoryResolver_emptyFileSystemID(t *testing.T) {
	resolver, err := NewFromDirectory("./testdata/image-symlinks", "")
	require.NoError(t, err)

	locations, err := resolver.FilesByGlob("**/*.txt")
	require.NoError(t, err)
	require.NotEmpty(t, locations)
	for _, l := range locations {
		assert.Empty(t, l.FileSystemID, "ordinary directory scan should not stamp a FileSystemID")
	}
}

// Test_DirectoryResolver_archiveRootIsNotALocation covers
// syft/archive-content-identity#nested-paths-are-archive-relative, scenario "enumerating all
// locations yields nothing outside the archive tree". ToChrootPath trims the prefix root + "/",
// which cannot match the root path itself, so AllLocations used to emit the resolver's own root
// with an absolute path. For an extracted archive that path is a temp directory created fresh per
// run: it reached FileMetadata, was copied into the shared SBOM, and gained a CONTAINS edge, so
// identical input produced different SBOMs.
func Test_DirectoryResolver_archiveRootIsNotALocation(t *testing.T) {
	// a directory standing in for an extracted archive, with a nested file so there is something
	// legitimate to enumerate alongside the root
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "lib"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "lib", "dep.txt"), []byte("dep"), 0o644))

	t.Run("an archive filesystem does not report its own root", func(t *testing.T) {
		resolver, err := NewFromDirectoryWithFS(root, "", "app/bundle.zip")
		require.NoError(t, err)

		var paths []string
		for l := range resolver.AllLocations(context.Background()) {
			assert.False(t, filepath.IsAbs(l.RealPath),
				"no location may carry an absolute path: %q", l.RealPath)
			assert.NotContains(t, l.RealPath, root,
				"the extraction directory must not appear in any location")
			paths = append(paths, l.RealPath)
		}
		assert.Contains(t, paths, "lib/dep.txt", "the archive's own contents must still be enumerated")
	})

	t.Run("a directory scan still reports its root", func(t *testing.T) {
		// the suppression is gated on a non-empty FileSystemID precisely so that released behavior
		// for directory and image scans is untouched: there the root is the path the user asked for
		resolver, err := NewFromDirectory(root, "")
		require.NoError(t, err)

		var sawAbsolute bool
		for l := range resolver.AllLocations(context.Background()) {
			if filepath.IsAbs(l.RealPath) {
				sawAbsolute = true
			}
		}
		assert.True(t, sawAbsolute, "a plain directory scan reports its root as it always has")
	})
}

// Test_DirectoryResolver_archivePathsAreRelative covers the other half of
// #nested-paths-are-archive-relative: the path, glob and MIME code paths report archive-relative
// paths. Nothing asserted this - the FileSystemID test above checks the identifier and never the
// path.
func Test_DirectoryResolver_archivePathsAreRelative(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "lib"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "lib", "dep.txt"), []byte("dep"), 0o644))

	resolver, err := NewFromDirectoryWithFS(root, "", "app/bundle.zip")
	require.NoError(t, err)

	assertRelative := func(t *testing.T, locations []file.Location) {
		t.Helper()
		require.NotEmpty(t, locations)
		for _, l := range locations {
			assert.Equal(t, "lib/dep.txt", l.RealPath)
			assert.NotContains(t, l.AccessPath, root)
		}
	}

	t.Run("FilesByPath", func(t *testing.T) {
		locations, err := resolver.FilesByPath("/lib/dep.txt")
		require.NoError(t, err)
		assertRelative(t, locations)
	})

	t.Run("FilesByGlob", func(t *testing.T) {
		locations, err := resolver.FilesByGlob("**/*.txt")
		require.NoError(t, err)
		assertRelative(t, locations)
	})

	t.Run("FilesByMIMEType", func(t *testing.T) {
		locations, err := resolver.FilesByMIMEType("text/plain")
		require.NoError(t, err)
		assertRelative(t, locations)
	})
}
