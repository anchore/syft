package directorysource

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/internal/testutil"
	"github.com/anchore/syft/syft/source"
)

func TestNewFromDirectory(t *testing.T) {
	testutil.Chdir(t, "..") // run with source/test-fixtures

	testCases := []struct {
		desc         string
		input        string
		expString    string
		inputPaths   []string
		expectedRefs int
		cxErr        require.ErrorAssertionFunc
	}{
		{
			desc:       "no paths exist",
			input:      "foobar/",
			inputPaths: []string{"/opt/", "/other"},
			cxErr:      require.Error,
		},
		{
			desc:         "path detected",
			input:        "test-fixtures",
			inputPaths:   []string{"path-detected/.vimrc"},
			expectedRefs: 1,
		},
		{
			desc:         "directory ignored",
			input:        "test-fixtures",
			inputPaths:   []string{"path-detected"},
			expectedRefs: 0,
		},
		{
			desc:         "no files-by-path detected",
			input:        "test-fixtures",
			inputPaths:   []string{"no-path-detected"},
			expectedRefs: 0,
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			if test.cxErr == nil {
				test.cxErr = require.NoError
			}
			src, err := New(Config{
				Path: test.input,
			})
			test.cxErr(t, err)
			if err != nil {
				return
			}
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, src.Close())
			})
			assert.Equal(t, test.input, src.Describe().Metadata.(source.DirectoryMetadata).Path)

			res, err := src.FileResolver(source.SquashedScope)
			require.NoError(t, err)

			refs, err := res.FilesByPath(test.inputPaths...)
			require.NoError(t, err)

			if len(refs) != test.expectedRefs {
				t.Errorf("unexpected number of refs returned: %d != %d", len(refs), test.expectedRefs)
			}

		})
	}
}

func Test_DirectorySource_FilesByGlob(t *testing.T) {
	testutil.Chdir(t, "..") // run with source/test-fixtures

	testCases := []struct {
		desc     string
		input    string
		glob     string
		expected int
	}{
		{
			input:    "test-fixtures",
			desc:     "no matches",
			glob:     "bar/foo",
			expected: 0,
		},
		{
			input:    "test-fixtures/path-detected",
			desc:     "a single match",
			glob:     "**/*vimrc",
			expected: 1,
		},
		{
			input:    "test-fixtures/path-detected",
			desc:     "multiple matches",
			glob:     "**",
			expected: 2,
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			src, err := New(Config{Path: test.input})
			require.NoError(t, err)

			res, err := src.FileResolver(source.SquashedScope)
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, src.Close())
			})

			contents, err := res.FilesByGlob(test.glob)
			require.NoError(t, err)
			if len(contents) != test.expected {
				t.Errorf("unexpected number of files found by glob (%s): %d != %d", test.glob, len(contents), test.expected)
			}

		})
	}
}

func Test_DirectorySource_Exclusions(t *testing.T) {
	testutil.Chdir(t, "..") // run with source/test-fixtures

	testCases := []struct {
		desc       string
		input      string
		glob       string
		expected   []string
		exclusions []string
		err        bool
	}{
		{
			input:      "test-fixtures/system_paths",
			desc:       "exclude everything",
			glob:       "**",
			expected:   nil,
			exclusions: []string{"**/*"},
		},
		{
			input: "test-fixtures/image-simple",
			desc:  "a single path excluded",
			glob:  "**",
			expected: []string{
				"Dockerfile",
				"file-1.txt",
				"file-2.txt",
			},
			exclusions: []string{"**/target/**"},
		},
		{
			input: "test-fixtures/image-simple",
			desc:  "exclude explicit directory relative to the root",
			glob:  "**",
			expected: []string{
				"Dockerfile",
				"file-1.txt",
				"file-2.txt",
				//"target/really/nested/file-3.txt", // explicitly skipped
			},
			exclusions: []string{"./target"},
		},
		{
			input: "test-fixtures/image-simple",
			desc:  "exclude explicit file relative to the root",
			glob:  "**",
			expected: []string{
				"Dockerfile",
				//"file-1.txt",  // explicitly skipped
				"file-2.txt",
				"target/really/nested/file-3.txt",
			},
			exclusions: []string{"./file-1.txt"},
		},
		{
			input: "test-fixtures/image-simple",
			desc:  "exclude wildcard relative to the root",
			glob:  "**",
			expected: []string{
				"Dockerfile",
				//"file-1.txt",  // explicitly skipped
				//"file-2.txt", // explicitly skipped
				"target/really/nested/file-3.txt",
			},
			exclusions: []string{"./*.txt"},
		},
		{
			input: "test-fixtures/image-simple",
			desc:  "exclude files deeper",
			glob:  "**",
			expected: []string{
				"Dockerfile",
				"file-1.txt",
				"file-2.txt",
				//"target/really/nested/file-3.txt", // explicitly skipped
			},
			exclusions: []string{"**/really/**"},
		},
		{
			input: "test-fixtures/image-simple",
			desc:  "files excluded with extension",
			glob:  "**",
			expected: []string{
				"Dockerfile",
				//"file-1.txt",  // explicitly skipped
				//"file-2.txt", // explicitly skipped
				//"target/really/nested/file-3.txt", // explicitly skipped
			},
			exclusions: []string{"**/*.txt"},
		},
		{
			input: "test-fixtures/image-simple",
			desc:  "keep files with different extensions",
			glob:  "**",
			expected: []string{
				"Dockerfile",
				"file-1.txt",
				"file-2.txt",
				"target/really/nested/file-3.txt",
			},
			exclusions: []string{"**/target/**/*.jar"},
		},
		{
			input: "test-fixtures/path-detected",
			desc:  "file directly excluded",
			glob:  "**",
			expected: []string{
				".vimrc",
			},
			exclusions: []string{"**/empty"},
		},
		{
			input: "test-fixtures/path-detected",
			desc:  "pattern error containing **/",
			glob:  "**",
			expected: []string{
				".vimrc",
			},
			exclusions: []string{"/**/empty"},
			err:        true,
		},
		{
			input: "test-fixtures/path-detected",
			desc:  "pattern error incorrect start",
			glob:  "**",
			expected: []string{
				".vimrc",
			},
			exclusions: []string{"empty"},
			err:        true,
		},
		{
			input: "test-fixtures/path-detected",
			desc:  "pattern error starting with /",
			glob:  "**",
			expected: []string{
				".vimrc",
			},
			exclusions: []string{"/empty"},
			err:        true,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			src, err := New(Config{
				Path: test.input,
				Exclude: source.ExcludeConfig{
					Paths: test.exclusions,
				},
			})
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, src.Close())
			})

			if test.err {
				_, err = src.FileResolver(source.SquashedScope)
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			res, err := src.FileResolver(source.SquashedScope)
			require.NoError(t, err)

			locations, err := res.FilesByGlob(test.glob)
			require.NoError(t, err)

			var actual []string
			for _, l := range locations {
				actual = append(actual, l.RealPath)
			}

			assert.ElementsMatchf(t, test.expected, actual, "diff \n"+cmp.Diff(test.expected, actual))
		})
	}
}

func Test_getDirectoryExclusionFunctions_crossPlatform(t *testing.T) {
	testCases := []struct {
		desc     string
		root     string
		path     string
		finfo    os.FileInfo
		exclude  string
		walkHint error
	}{
		{
			desc:     "directory exclusion",
			root:     "/",
			path:     "/usr/var/lib",
			exclude:  "**/var/lib",
			finfo:    file.ManualInfo{ModeValue: os.ModeDir},
			walkHint: fs.SkipDir,
		},
		{
			desc:     "no file info",
			root:     "/",
			path:     "/usr/var/lib",
			exclude:  "**/var/lib",
			walkHint: fileresolver.ErrSkipPath,
		},
		// linux specific tests...
		{
			desc:     "linux doublestar",
			root:     "/usr",
			path:     "/usr/var/lib/etc.txt",
			exclude:  "**/*.txt",
			finfo:    file.ManualInfo{},
			walkHint: fileresolver.ErrSkipPath,
		},
		{
			desc:    "linux relative",
			root:    "/usr/var/lib",
			path:    "/usr/var/lib/etc.txt",
			exclude: "./*.txt",
			finfo:   file.ManualInfo{},

			walkHint: fileresolver.ErrSkipPath,
		},
		{
			desc:     "linux one level",
			root:     "/usr",
			path:     "/usr/var/lib/etc.txt",
			exclude:  "*/*.txt",
			finfo:    file.ManualInfo{},
			walkHint: nil,
		},
		// NOTE: since these tests will run in linux and macOS, the windows paths will be
		// considered relative if they do not start with a forward slash and paths with backslashes
		// won't be modified by the filepath.ToSlash call, so these are emulating the result of
		// filepath.ToSlash usage

		// windows specific tests...
		{
			desc:     "windows doublestar",
			root:     "/C:/User/stuff",
			path:     "/C:/User/stuff/thing.txt",
			exclude:  "**/*.txt",
			finfo:    file.ManualInfo{},
			walkHint: fileresolver.ErrSkipPath,
		},
		{
			desc:     "windows relative",
			root:     "/C:/User/stuff",
			path:     "/C:/User/stuff/thing.txt",
			exclude:  "./*.txt",
			finfo:    file.ManualInfo{},
			walkHint: fileresolver.ErrSkipPath,
		},
		{
			desc:     "windows one level",
			root:     "/C:/User/stuff",
			path:     "/C:/User/stuff/thing.txt",
			exclude:  "*/*.txt",
			finfo:    file.ManualInfo{},
			walkHint: nil,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			fns, err := GetDirectoryExclusionFunctions(test.root, []string{test.exclude})
			require.NoError(t, err)

			for _, f := range fns {
				result := f("", test.path, test.finfo, nil)
				require.Equal(t, test.walkHint, result)
			}
		})
	}
}

func Test_DirectorySource_FilesByPathDoesNotExist(t *testing.T) {
	testutil.Chdir(t, "..") // run with source/test-fixtures

	testCases := []struct {
		desc     string
		input    string
		path     string
		expected string
	}{
		{
			input: "test-fixtures/path-detected",
			desc:  "path does not exist",
			path:  "foo",
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			src, err := New(Config{Path: test.input})
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, src.Close())
			})

			res, err := src.FileResolver(source.SquashedScope)
			require.NoError(t, err)

			refs, err := res.FilesByPath(test.path)
			require.NoError(t, err)

			assert.Len(t, refs, 0)
		})
	}
}

func Test_DirectorySource_ID(t *testing.T) {
	testutil.Chdir(t, "..") // run with source/test-fixtures

	tests := []struct {
		name    string
		cfg     Config
		want    artifact.ID
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:    "empty",
			cfg:     Config{},
			wantErr: require.Error,
		},
		{
			name: "to a non-existent directory",
			cfg: Config{
				Path: "./test-fixtures/does-not-exist",
			},
			wantErr: require.Error,
		},
		{
			name:    "with odd unclean path through non-existent directory",
			cfg:     Config{Path: "test-fixtures/does-not-exist/../"},
			wantErr: require.Error,
		},
		{
			name: "to a file (not a directory)",
			cfg: Config{
				Path: "./test-fixtures/image-simple/Dockerfile",
			},
			wantErr: require.Error,
		},
		{
			name: "to dir with name and version",
			cfg: Config{
				Path: "./test-fixtures",
				Alias: source.Alias{
					Name:    "name-me-that!",
					Version: "version-me-this!",
				},
			},
			want: artifact.ID("51a5f2a1536cf4b5220d4247814b07eec5862ab0547050f90e9ae216548ded7e"),
		},
		{
			name: "to different dir with name and version",
			cfg: Config{
				Path: "./test-fixtures/image-simple",
				Alias: source.Alias{
					Name:    "name-me-that!",
					Version: "version-me-this!",
				},
			},
			// note: this must match the previous value because the alias should trump the path info
			want: artifact.ID("51a5f2a1536cf4b5220d4247814b07eec5862ab0547050f90e9ae216548ded7e"),
		},
		{
			name: "with path",
			cfg:  Config{Path: "./test-fixtures"},
			want: artifact.ID("c2f936b0054dc6114fc02a3446bf8916bde8fdf87166a23aee22ea011b443522"),
		},
		{
			name: "with unclean path",
			cfg:  Config{Path: "test-fixtures/image-simple/../"},
			want: artifact.ID("c2f936b0054dc6114fc02a3446bf8916bde8fdf87166a23aee22ea011b443522"),
		},
		{
			name: "other fields do not affect ID",
			cfg: Config{
				Path: "test-fixtures",
				Base: "a-base!",
				Exclude: source.ExcludeConfig{
					Paths: []string{"a", "b"},
				},
			},
			want: artifact.ID("c2f936b0054dc6114fc02a3446bf8916bde8fdf87166a23aee22ea011b443522"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			s, err := New(tt.cfg)
			tt.wantErr(t, err)
			if err != nil {
				return
			}
			assert.Equalf(t, tt.want, s.ID(), "ID()")
		})
	}
}

func Test_cleanDirPath(t *testing.T) {
	testutil.Chdir(t, "..") // run with source/test-fixtures

	abs, err := filepath.Abs("test-fixtures")
	require.NoError(t, err)

	tests := []struct {
		name string
		path string
		base string
		want string
	}{
		{
			name: "abs path, abs base, base contained in path",
			path: filepath.Join(abs, "system_paths/outside_root"),
			base: abs,
			want: "system_paths/outside_root",
		},
		{
			name: "abs path, abs base, base not contained in path",
			path: "/var/folders/8x/gw98pp6535s4r8drc374tb1r0000gn/T/001/some/path",
			base: "/var/folders/8x/gw98pp6535s4r8drc374tb1r0000gn/T/002",
			want: "/var/folders/8x/gw98pp6535s4r8drc374tb1r0000gn/T/001/some/path",
		},
		{
			name: "path and base match",
			path: "/var/folders/8x/gw98pp6535s4r8drc374tb1r0000gn/T/001/some/path",
			base: "/var/folders/8x/gw98pp6535s4r8drc374tb1r0000gn/T/001/some/path",
			want: "/var/folders/8x/gw98pp6535s4r8drc374tb1r0000gn/T/001/some/path",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, cleanDirPath(tt.path, tt.base))
		})
	}
}
