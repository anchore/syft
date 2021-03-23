package source

import (
	"os"
	"testing"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/stretchr/testify/assert"
)

func TestFileMetadataFetch(t *testing.T) {
	img := imagetest.GetFixtureImage(t, "docker-archive", "image-file-type-mix")

	tests := []struct {
		path     string
		exists   bool
		expected FileMetadata
		err      bool
	}{
		{
			path:   "/file-1.txt",
			exists: true,
			expected: FileMetadata{
				Mode:    0644,
				Type:    "regularFile",
				UserID:  1,
				GroupID: 2,
			},
		},
		{
			path:   "/hardlink-1",
			exists: true,
			expected: FileMetadata{
				Mode:    0644,
				Type:    "hardLink",
				UserID:  1,
				GroupID: 2,
			},
		},
		{
			path:   "/symlink-1",
			exists: true,
			expected: FileMetadata{
				Mode:    0777 | os.ModeSymlink,
				Type:    "symbolicLink",
				UserID:  0,
				GroupID: 0,
			},
		},
		{
			path:   "/char-device-1",
			exists: true,
			expected: FileMetadata{
				Mode:    0644 | os.ModeDevice | os.ModeCharDevice,
				Type:    "characterDevice",
				UserID:  0,
				GroupID: 0,
			},
		},
		{
			path:   "/block-device-1",
			exists: true,
			expected: FileMetadata{
				Mode:    0644 | os.ModeDevice,
				Type:    "blockDevice",
				UserID:  0,
				GroupID: 0,
			},
		},
		{
			path:   "/fifo-1",
			exists: true,
			expected: FileMetadata{
				Mode:    0644 | os.ModeNamedPipe,
				Type:    "fifoNode",
				UserID:  0,
				GroupID: 0,
			},
		},
		{
			path:   "/bin",
			exists: true,
			expected: FileMetadata{
				Mode:    0755 | os.ModeDir,
				Type:    "directory",
				UserID:  0,
				GroupID: 0,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			exists, ref, err := img.SquashedTree().File(file.Path(test.path))
			if err != nil {
				t.Fatalf("unable to get file: %+v", err)
			}

			if exists && !test.exists {
				t.Fatalf("file=%q exists but shouldn't", test.path)
			} else if !exists && test.exists {
				t.Fatalf("file=%q does not exist but should", test.path)
			} else if !exists && !test.exists {
				return
			}

			actual, err := fileMetadataByLocation(img, NewLocationFromImage(test.path, *ref, img))
			if err != nil && !test.err {
				t.Fatalf("could not fetch (but should have been able to): %+v", err)
			} else if err == nil && test.err {
				t.Fatalf("expected fetch error but did not get one")
			} else if test.err && err != nil {
				return
			}

			assert.Equal(t, test.expected, actual, "file metadata mismatch")

		})
	}

}
