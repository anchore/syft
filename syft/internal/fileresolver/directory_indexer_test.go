package fileresolver

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/stereoscope/pkg/file"
)

type indexerMock struct {
	observedRoots   []string
	additionalRoots map[string][]string
}

func (m *indexerMock) indexer(s string, _ *progress.Stage) ([]string, error) {
	m.observedRoots = append(m.observedRoots, s)
	return m.additionalRoots[s], nil
}

func Test_indexAllRoots(t *testing.T) {
	tests := []struct {
		name          string
		root          string
		mock          indexerMock
		expectedRoots []string
	}{
		{
			name: "no additional roots",
			root: "a/place",
			mock: indexerMock{
				additionalRoots: make(map[string][]string),
			},
			expectedRoots: []string{
				"a/place",
			},
		},
		{
			name: "additional roots from a single call",
			root: "a/place",
			mock: indexerMock{
				additionalRoots: map[string][]string{
					"a/place": {
						"another/place",
						"yet-another/place",
					},
				},
			},
			expectedRoots: []string{
				"a/place",
				"another/place",
				"yet-another/place",
			},
		},
		{
			name: "additional roots from a multiple calls",
			root: "a/place",
			mock: indexerMock{
				additionalRoots: map[string][]string{
					"a/place": {
						"another/place",
						"yet-another/place",
					},
					"yet-another/place": {
						"a-quiet-place-2",
						"a-final/place",
					},
				},
			},
			expectedRoots: []string{
				"a/place",
				"another/place",
				"yet-another/place",
				"a-quiet-place-2",
				"a-final/place",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.NoError(t, indexAllRoots(test.root, test.mock.indexer))
		})
	}
}

func TestDirectoryIndexer_handleFileAccessErr(t *testing.T) {
	tests := []struct {
		name                string
		input               error
		expectedPathTracked bool
	}{
		{
			name:                "permission error does not propagate",
			input:               os.ErrPermission,
			expectedPathTracked: true,
		},
		{
			name:                "file does not exist error does not propagate",
			input:               os.ErrNotExist,
			expectedPathTracked: true,
		},
		{
			name:                "non-permission errors are tracked",
			input:               os.ErrInvalid,
			expectedPathTracked: true,
		},
		{
			name:                "non-errors ignored",
			input:               nil,
			expectedPathTracked: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := directoryIndexer{
				errPaths: make(map[string]error),
			}
			p := "a/place"
			assert.Equal(t, r.isFileAccessErr(p, test.input), test.expectedPathTracked)
			_, exists := r.errPaths[p]
			assert.Equal(t, test.expectedPathTracked, exists)
		})
	}
}

func TestDirectoryIndexer_IncludeRootPathInIndex(t *testing.T) {
	filterFn := func(_, path string, _ os.FileInfo, _ error) error {
		if path != "/" {
			return fs.SkipDir
		}
		return nil
	}

	indexer := newDirectoryIndexer("/", "", filterFn)
	tree, index, err := indexer.build()
	require.NoError(t, err)

	exists, ref, err := tree.File(file.Path("/"))
	require.NoError(t, err)
	require.NotNil(t, ref)
	assert.True(t, exists)

	_, err = index.Get(*ref.Reference)
	require.NoError(t, err)
}

func TestDirectoryIndexer_indexPath_skipsNilFileInfo(t *testing.T) {
	// TODO: Ideally we can use an OS abstraction, which would obviate the need for real FS setup.
	tempFile, err := os.CreateTemp("", "")
	require.NoError(t, err)

	indexer := newDirectoryIndexer(tempFile.Name(), "")

	t.Run("filtering path with nil os.FileInfo", func(t *testing.T) {
		assert.NotPanics(t, func() {
			_, err := indexer.indexPath("/dont-care", nil, nil)
			assert.NoError(t, err)
			assert.False(t, indexer.tree.HasPath("/dont-care"))
		})
	})
}

func TestDirectoryIndexer_index(t *testing.T) {
	// note: this test is testing the effects from NewFromDirectory, indexTree, and addPathToIndex
	indexer := newDirectoryIndexer("test-fixtures/system_paths/target", "")
	tree, index, err := indexer.build()
	require.NoError(t, err)

	tests := []struct {
		name string
		path string
	}{
		{
			name: "has dir",
			path: "test-fixtures/system_paths/target/home",
		},
		{
			name: "has path",
			path: "test-fixtures/system_paths/target/home/place",
		},
		{
			name: "has symlink",
			path: "test-fixtures/system_paths/target/link/a-symlink",
		},
		{
			name: "has symlink target",
			path: "test-fixtures/system_paths/outside_root/link_target/place",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info, err := os.Stat(test.path)
			assert.NoError(t, err)

			// note: the index uses absolute paths, so assertions MUST keep this in mind
			cwd, err := os.Getwd()
			require.NoError(t, err)

			p := file.Path(path.Join(cwd, test.path))
			assert.Equal(t, true, tree.HasPath(p))
			exists, ref, err := tree.File(p)
			assert.Equal(t, true, exists)
			if assert.NoError(t, err) {
				return
			}

			entry, err := index.Get(*ref.Reference)
			require.NoError(t, err)
			assert.Equal(t, info.Mode(), entry.Mode)
		})
	}
}

func TestDirectoryIndexer_index_survive_badSymlink(t *testing.T) {
	// test-fixtures/bad-symlinks
	// ├── root
	// │   ├── place
	// │   │   └── fd -> ../somewhere/self/fd
	// │   └── somewhere
	// ...
	indexer := newDirectoryIndexer("test-fixtures/bad-symlinks/root/place/fd", "test-fixtures/bad-symlinks/root/place/fd")
	_, _, err := indexer.build()
	require.NoError(t, err)
}

func TestDirectoryIndexer_SkipsAlreadyVisitedLinkDestinations(t *testing.T) {
	var observedPaths []string
	pathObserver := func(_, p string, _ os.FileInfo, _ error) error {
		fields := strings.Split(p, "test-fixtures/symlinks-prune-indexing")
		if len(fields) < 2 {
			return nil
		}
		clean := strings.TrimLeft(fields[1], "/")
		if clean != "" {
			observedPaths = append(observedPaths, clean)
		}
		return nil
	}
	resolver := newDirectoryIndexer("./test-fixtures/symlinks-prune-indexing", "")
	// we want to cut ahead of any possible filters to see what paths are considered for indexing (closest to walking)
	resolver.pathIndexVisitors = append([]PathIndexVisitor{pathObserver}, resolver.pathIndexVisitors...)

	// note: this test is NOT about the effects left on the tree or the index, but rather the WHICH paths that are
	// considered for indexing and HOW traversal prunes paths that have already been visited
	_, _, err := resolver.build()
	require.NoError(t, err)

	expected := []string{
		"before-path",
		"c-file.txt",
		"c-path",
		"path",
		"path/1",
		"path/1/2",
		"path/1/2/3",
		"path/1/2/3/4",
		"path/1/2/3/4/dont-index-me-twice.txt",
		"path/5",
		"path/5/6",
		"path/5/6/7",
		"path/5/6/7/8",
		"path/5/6/7/8/dont-index-me-twice-either.txt",
		"path/file.txt",
		// everything below is after the original tree is indexed, and we are now indexing additional roots from symlinks
		"path",          // considered from symlink before-path, but pruned
		"path/file.txt", // leaf
		"before-path",   // considered from symlink c-path, but pruned
		"path/file.txt", // leaf
		"before-path",   // considered from symlink c-path, but pruned
	}

	assert.Equal(t, expected, observedPaths, "visited paths differ \n %s", cmp.Diff(expected, observedPaths))

}

func TestDirectoryIndexer_IndexesAllTypes(t *testing.T) {
	indexer := newDirectoryIndexer("./test-fixtures/symlinks-prune-indexing", "")

	tree, index, err := indexer.build()
	require.NoError(t, err)

	allRefs := tree.AllFiles(file.AllTypes()...)
	var pathRefs []file.Reference
	paths := strset.New()
	for _, ref := range allRefs {
		fields := strings.Split(string(ref.RealPath), "test-fixtures/symlinks-prune-indexing")
		if len(fields) != 2 {
			continue
		}
		clean := strings.TrimLeft(fields[1], "/")
		if clean == "" {
			continue
		}
		paths.Add(clean)
		pathRefs = append(pathRefs, ref)
	}

	pathsList := paths.List()
	sort.Strings(pathsList)

	expected := []string{
		"before-path",                          // link
		"c-file.txt",                           // link
		"c-path",                               // link
		"path",                                 // dir
		"path/1",                               // dir
		"path/1/2",                             // dir
		"path/1/2/3",                           // dir
		"path/1/2/3/4",                         // dir
		"path/1/2/3/4/dont-index-me-twice.txt", // file
		"path/5",                               // dir
		"path/5/6",                             // dir
		"path/5/6/7",                           // dir
		"path/5/6/7/8",                         // dir
		"path/5/6/7/8/dont-index-me-twice-either.txt", // file
		"path/file.txt", // file
	}
	expectedSet := strset.New(expected...)

	// make certain all expected paths are in the tree (and no extra ones are their either)

	assert.True(t, paths.IsEqual(expectedSet), "expected all paths to be indexed, but found different paths: \n%s", cmp.Diff(expected, pathsList))

	// make certain that the paths are also in the file index

	for _, ref := range pathRefs {
		_, err := index.Get(ref)
		require.NoError(t, err)
	}

}

func Test_allContainedPaths(t *testing.T) {

	tests := []struct {
		name string
		path string
		want []string
	}{
		{
			name: "empty",
			path: "",
			want: nil,
		},
		{
			name: "single relative",
			path: "a",
			want: []string{"a"},
		},
		{
			name: "single absolute",
			path: "/a",
			want: []string{"/a"},
		},
		{
			name: "multiple relative",
			path: "a/b/c",
			want: []string{"a", "a/b", "a/b/c"},
		},
		{
			name: "multiple absolute",
			path: "/a/b/c",
			want: []string{"/a", "/a/b", "/a/b/c"},
		},
		{
			name: "multiple absolute with extra slashs",
			path: "///a/b//c/",
			want: []string{"/a", "/a/b", "/a/b/c"},
		},
		{
			name: "relative with single dot",
			path: "a/./b",
			want: []string{"a", "a/b"},
		},
		{
			name: "relative with double single dot",
			path: "a/../b",
			want: []string{"b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, allContainedPaths(tt.path))
		})
	}
}

func Test_relativePath(t *testing.T) {
	tests := []struct {
		name      string
		basePath  string
		givenPath string
		want      string
	}{
		{
			name:      "root: same relative path",
			basePath:  "a/b/c",
			givenPath: "a/b/c",
			want:      "/",
		},
		{
			name:      "root: same absolute path",
			basePath:  "/a/b/c",
			givenPath: "/a/b/c",
			want:      "/",
		},
		{
			name:      "contained path: relative",
			basePath:  "a/b/c",
			givenPath: "a/b/c/dev",
			want:      "/dev",
		},
		{
			name:      "contained path: absolute",
			basePath:  "/a/b/c",
			givenPath: "/a/b/c/dev",
			want:      "/dev",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, relativePath(tt.basePath, tt.givenPath))
		})
	}
}

func relativePath(basePath, givenPath string) string {
	var relPath string
	var relErr error

	if basePath != "" {
		relPath, relErr = filepath.Rel(basePath, givenPath)
		cleanPath := filepath.Clean(relPath)
		if relErr == nil {
			if cleanPath == "." {
				relPath = string(filepath.Separator)
			} else {
				relPath = cleanPath
			}
		}
		if !filepath.IsAbs(relPath) {
			relPath = string(filepath.Separator) + relPath
		}
	}

	if relErr != nil || basePath == "" {
		relPath = givenPath
	}

	return relPath
}
