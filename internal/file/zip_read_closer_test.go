//go:build !windows
// +build !windows

package file

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFindArchiveStartOffset(t *testing.T) {
	tests := []struct {
		name        string
		archivePrep func(tb testing.TB) string
		expected    uint64
	}{
		{
			name:        "standard, non-nested zip",
			archivePrep: prepZipSourceFixture,
			expected:    0,
		},
		{
			name:        "zip with prepended bytes",
			archivePrep: prependZipSourceFixtureWithString(t, "junk at the beginning of the file..."),
			expected:    36,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archivePath := test.archivePrep(t)
			f, err := os.Open(archivePath)
			if err != nil {
				t.Fatalf("could not open archive %q: %+v", archivePath, err)
			}
			fi, err := os.Stat(f.Name())
			if err != nil {
				t.Fatalf("unable to stat archive: %+v", err)
			}

			actual, err := findArchiveStartOffset(f, fi.Size())
			if err != nil {
				t.Fatalf("unable to find offset: %+v", err)
			}
			assert.Equal(t, test.expected, actual)
		})
	}
}
