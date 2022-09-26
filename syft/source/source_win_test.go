//go:build windows
// +build windows

package source

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_crossPlatformExclusions(t *testing.T) {
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
			fns, err := getDirectoryExclusionFunctions(test.root, []string{test.exclude})
			require.NoError(t, err)

			for _, f := range fns {
				result := f(test.path, nil)
				require.Equal(t, test.match, result)
			}
		})
	}
}
