//go:build windows
// +build windows

// why the build tags? there is behavior from filepath.ToSlash() that must be tested, but can't be tested on non-windows
// since the stdlib keeps this functionality behind a build tag (specifically filepath.Separator):
//   - https://github.com/golang/go/blob/3aea422e2cb8b1ec2e0c2774be97fe96c7299838/src/path/filepath/path.go#L224-L227
//   - https://github.com/golang/go/blob/3aea422e2cb8b1ec2e0c2774be97fe96c7299838/src/path/filepath/path.go#L63
//   - https://github.com/golang/go/blob/master/src/os/path_windows.go#L8
//
// It would be nice to extract this to simplify testing, however, we also need filepath.Abs(), which in windows
// requires a specific syscall:
//   - https://github.com/golang/go/blob/3aea422e2cb8b1ec2e0c2774be97fe96c7299838/src/path/filepath/path_windows.go#L216
// ... which means we can't extract this functionality without build tags.

package directorysource

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_DirectorySource_crossPlatformExclusions(t *testing.T) {
	testCases := []struct {
		desc    string
		root    string
		path    string
		exclude string
		match   bool
	}{
		{
			desc:    "windows doublestar",
			root:    "C:\\User\\stuff",
			path:    "C:\\User\\stuff\\thing.txt",
			exclude: "**/*.txt",
			match:   true,
		},
		{
			desc:    "windows relative",
			root:    "C:\\User\\stuff",
			path:    "C:\\User\\stuff\\thing.txt",
			exclude: "./*.txt",
			match:   true,
		},
		{
			desc:    "windows one level",
			root:    "C:\\User\\stuff",
			path:    "C:\\User\\stuff\\thing.txt",
			exclude: "*/*.txt",
			match:   false,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			fns, err := GetDirectoryExclusionFunctions(test.root, []string{test.exclude})
			require.NoError(t, err)

			for _, f := range fns {
				result := f(test.path, nil, nil)
				require.Equal(t, test.match, result)
			}
		})
	}
}
