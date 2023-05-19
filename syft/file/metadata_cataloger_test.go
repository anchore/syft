package file

import (
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/source"
)

var updateImageGoldenFiles = flag.Bool("update-image", false, "update the golden fixture images used for testing")

func TestFileMetadataCataloger(t *testing.T) {
	testImage := "image-file-type-mix"

	if *updateImageGoldenFiles {
		imagetest.UpdateGoldenFixtureImage(t, testImage)
	}

	img := imagetest.GetGoldenFixtureImage(t, testImage)

	c := NewMetadataCataloger()

	src, err := source.NewFromImage(img, "---")
	if err != nil {
		t.Fatalf("could not create source: %+v", err)
	}

	resolver, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		t.Fatalf("could not create resolver: %+v", err)
	}

	actual, err := c.Catalog(resolver)
	if err != nil {
		t.Fatalf("could not catalog: %+v", err)
	}

	tests := []struct {
		path     string
		exists   bool
		expected source.FileMetadata
		err      bool
	}{
		{
			path:   "/file-1.txt",
			exists: true,
			expected: source.FileMetadata{
				FileInfo: file.ManualInfo{
					NameValue: "file-1.txt",
					ModeValue: 0644,
					SizeValue: 7,
				},
				Path:     "/file-1.txt",
				Type:     file.TypeRegular,
				UserID:   1,
				GroupID:  2,
				MIMEType: "text/plain",
			},
		},
		{
			path:   "/hardlink-1",
			exists: true,
			expected: source.FileMetadata{
				FileInfo: file.ManualInfo{
					NameValue: "hardlink-1",
					ModeValue: 0644,
				},
				Path:            "/hardlink-1",
				Type:            file.TypeHardLink,
				LinkDestination: "file-1.txt",
				UserID:          1,
				GroupID:         2,
				MIMEType:        "",
			},
		},
		{
			path:   "/symlink-1",
			exists: true,
			expected: source.FileMetadata{
				Path: "/symlink-1",
				FileInfo: file.ManualInfo{
					NameValue: "symlink-1",
					ModeValue: 0777 | os.ModeSymlink,
				},
				Type:            file.TypeSymLink,
				LinkDestination: "file-1.txt",
				UserID:          0,
				GroupID:         0,
				MIMEType:        "",
			},
		},
		{
			path:   "/char-device-1",
			exists: true,
			expected: source.FileMetadata{
				Path: "/char-device-1",
				FileInfo: file.ManualInfo{
					NameValue: "char-device-1",
					ModeValue: 0644 | os.ModeDevice | os.ModeCharDevice,
				},
				Type:     file.TypeCharacterDevice,
				UserID:   0,
				GroupID:  0,
				MIMEType: "",
			},
		},
		{
			path:   "/block-device-1",
			exists: true,
			expected: source.FileMetadata{
				Path: "/block-device-1",
				FileInfo: file.ManualInfo{
					NameValue: "block-device-1",
					ModeValue: 0644 | os.ModeDevice,
				},
				Type:     file.TypeBlockDevice,
				UserID:   0,
				GroupID:  0,
				MIMEType: "",
			},
		},
		{
			path:   "/fifo-1",
			exists: true,
			expected: source.FileMetadata{
				Path: "/fifo-1",
				FileInfo: file.ManualInfo{
					NameValue: "fifo-1",
					ModeValue: 0644 | os.ModeNamedPipe,
				},
				Type:     file.TypeFIFO,
				UserID:   0,
				GroupID:  0,
				MIMEType: "",
			},
		},
		{
			path:   "/bin",
			exists: true,
			expected: source.FileMetadata{
				Path: "/bin",
				FileInfo: file.ManualInfo{
					NameValue: "bin",
					ModeValue: 0755 | os.ModeDir,
				},
				Type:     file.TypeDirectory,
				UserID:   0,
				GroupID:  0,
				MIMEType: "",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			_, ref, err := img.SquashedTree().File(file.Path(test.path))
			require.NoError(t, err)

			l := source.NewLocationFromImage(test.path, *ref.Reference, img)

			if _, ok := actual[l.Coordinates]; ok {
				// we're not interested in keeping the test fixtures up to date with the latest file modification times
				// thus ModTime is not under test
				fi := test.expected.FileInfo.(file.ManualInfo)
				fi.ModTimeValue = actual[l.Coordinates].ModTime()
				test.expected.FileInfo = fi
			}

			assert.True(t, test.expected.Equal(actual[l.Coordinates]))
		})
	}

}
