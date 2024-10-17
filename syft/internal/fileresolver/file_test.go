package fileresolver

import (
	"context"
	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/file"
	"github.com/google/go-cmp/cmp"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestFileResolver_FilesByPath(t *testing.T) {
	tests := []struct {
		description        string
		filePath           string // relative to cwd
		fileByPathInput    string
		expectedRealPath   string
		expectedAccessPath string
		cwd                string
	}{
		{
			description:        "Finds file if searched by filepath",
			filePath:           "./test-fixtures/req-resp/path/to/the/file.txt",
			fileByPathInput:    "file.txt",
			expectedRealPath:   "/file.txt",
			expectedAccessPath: "/file.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			parentPath, err := absoluteSymlinkFreePathToParent(tt.filePath)
			require.NoError(t, err)
			require.NotNil(t, parentPath)

			resolver, err := NewFromFile(parentPath, tt.filePath)
			require.NoError(t, err)
			require.NotNil(t, resolver)

			refs, err := resolver.FilesByPath(tt.fileByPathInput)
			require.NoError(t, err)
			if tt.expectedRealPath == "" {
				require.Empty(t, refs)
				return
			}
			require.Len(t, refs, 1)
			assert.Equal(t, tt.expectedRealPath, refs[0].RealPath, "real path different")
			assert.Equal(t, tt.expectedAccessPath, refs[0].AccessPath, "virtual path different")
		})
	}
}

// Test mutliple files by path -> Maybe not necessary for us here?
func TestFileResolver_MultipleFilesByPath(t *testing.T) {
	tests := []struct {
		description string
		input       []string
		refCount    int
	}{
		{
			description: "finds file ",
			input:       []string{"file.txt"},
			refCount:    1,
		},
		{
			description: "skip non-existing files",
			input:       []string{"file.txt", "bogus.txt"},
			refCount:    1,
		},
		{
			description: "does not return anything for non-existing files",
			input:       []string{"non-existing/bogus.txt", "another-bogus.txt"},
			refCount:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			filePath := "./test-fixtures/req-resp/path/to/the/file.txt"
			parentPath, err := absoluteSymlinkFreePathToParent(filePath)
			require.NoError(t, err)
			require.NotNil(t, parentPath)

			resolver, err := NewFromFile(parentPath, filePath)
			assert.NoError(t, err)
			refs, err := resolver.FilesByPath(tt.input...)
			assert.NoError(t, err)

			if len(refs) != tt.refCount {
				t.Errorf("unexpected number of refs: %d != %d", len(refs), tt.refCount)
			}
		})
	}
}

func TestFileResolver_FilesByGlob(t *testing.T) {
	filePath := "./test-fixtures/req-resp/path/to/the/file.txt"
	parentPath, err := absoluteSymlinkFreePathToParent(filePath)
	require.NoError(t, err)
	require.NotNil(t, parentPath)

	resolver, err := NewFromFile(parentPath, filePath)
	assert.NoError(t, err)
	refs, err := resolver.FilesByGlob("*.txt")
	assert.NoError(t, err)

	assert.Len(t, refs, 1)
}

func Test_fileResolver_FilesByMIMEType(t *testing.T) {
	tests := []struct {
		fixturePath   string
		mimeType      string
		expectedPaths *strset.Set
	}{
		{
			fixturePath:   "./test-fixtures/image-simple/file-1.txt",
			mimeType:      "text/plain",
			expectedPaths: strset.New("/file-1.txt"),
		},
	}
	for _, test := range tests {
		t.Run(test.fixturePath, func(t *testing.T) {
			filePath := "./test-fixtures/image-simple/file-1.txt"
			parentPath, err := absoluteSymlinkFreePathToParent(filePath)
			require.NoError(t, err)
			require.NotNil(t, parentPath)

			resolver, err := NewFromFile(parentPath, filePath)
			assert.NoError(t, err)
			locations, err := resolver.FilesByMIMEType(test.mimeType)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedPaths.Size(), len(locations))
			for _, l := range locations {
				assert.True(t, test.expectedPaths.Has(l.RealPath), "does not have path %q", l.RealPath)
			}
		})
	}
}

func Test_fileResolver_FileContentsByLocation(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	filePath := "./test-fixtures/image-simple/file-1.txt"
	parentPath, err := absoluteSymlinkFreePathToParent(filePath)
	require.NoError(t, err)
	require.NotNil(t, parentPath)

	r, err := NewFromFile(parentPath, filePath)
	require.NoError(t, err)

	exists, existingPath, err := r.tree.File(stereoscopeFile.Path(filepath.Join(cwd, "test-fixtures/image-simple/file-1.txt")))
	require.True(t, exists)
	require.NoError(t, err)
	require.True(t, existingPath.HasReference())

	tests := []struct {
		name     string
		location file.Location
		expects  string
		err      bool
	}{
		{
			name:     "use file reference for content requests",
			location: file.NewLocationFromDirectory("some/place", *existingPath.Reference),
			expects:  "this file has contents",
		},
		{
			name:     "error on empty file reference",
			location: file.NewLocationFromDirectory("doesn't matter", stereoscopeFile.Reference{}),
			err:      true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			actual, err := r.FileContentsByLocation(test.location)
			if test.err {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			if test.expects != "" {
				b, err := io.ReadAll(actual)
				require.NoError(t, err)
				assert.Equal(t, test.expects, string(b))
			}
		})
	}
}

func TestFileResolver_AllLocations_errorOnDirRequest(t *testing.T) {
	defer goleak.VerifyNone(t)

	filePath := "./test-fixtures/system_paths/target/home/place"
	parentPath, err := absoluteSymlinkFreePathToParent(filePath)
	require.NoError(t, err)
	require.NotNil(t, parentPath)
	resolver, err := NewFromFile(parentPath, filePath)
	require.NoError(t, err)

	var dirLoc *file.Location
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for loc := range resolver.AllLocations(ctx) {
		entry, err := resolver.index.Get(loc.Reference())
		require.NoError(t, err)
		if entry.Metadata.IsDir() {
			dirLoc = &loc
			break
		}
	}

	require.NotNil(t, dirLoc)

	reader, err := resolver.FileContentsByLocation(*dirLoc)
	require.Error(t, err)
	require.Nil(t, reader)
}

func TestFileResolver_AllLocations(t *testing.T) {
	// Verify both the parent and the file itself are indexed
	filePath := "./test-fixtures/system_paths/target/home/place"
	parentPath, err := absoluteSymlinkFreePathToParent(filePath)
	require.NoError(t, err)
	require.NotNil(t, parentPath)
	resolver, err := NewFromFile(parentPath, filePath)
	require.NoError(t, err)

	paths := strset.New()
	for loc := range resolver.AllLocations(context.Background()) {
		paths.Add(loc.RealPath)
	}
	expected := []string{
		"/place",
		"", // This is how we see the parent dir, since we're resolving wrt the parent directory.
	}

	pathsList := paths.List()
	sort.Strings(pathsList)

	assert.ElementsMatchf(t, expected, pathsList, "expected all paths to be indexed, but found different paths: \n%s", cmp.Diff(expected, paths.List()))
}

func Test_AllLocationsDoesNotLeakGoRoutine(t *testing.T) {
	defer goleak.VerifyNone(t)
	filePath := "./test-fixtures/system_paths/target/home/place"
	parentPath, err := absoluteSymlinkFreePathToParent(filePath)
	require.NoError(t, err)
	require.NotNil(t, parentPath)
	resolver, err := NewFromFile(parentPath, filePath)
	require.NoError(t, err)

	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	for range resolver.AllLocations(ctx) {
		break
	}
	cancel()
}
