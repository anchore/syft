package source

import (
	"io/fs"
	"os"
	"testing"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/stretchr/testify/require"
)

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
