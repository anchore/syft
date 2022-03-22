package filemetadata

import (
	"os"
	"testing"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
)

func TestFileMetadataCataloger(t *testing.T) {
	img := imagetest.GetFixtureImage(t, "docker-archive", "image-file-type-mix")

	c := NewCataloger()

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
		expected file.Metadata
		err      bool
	}{
		{
			path:   "/file-1.txt",
			exists: true,
			expected: file.Metadata{
				Mode:     0644,
				Type:     "RegularFile",
				UserID:   1,
				GroupID:  2,
				Size:     7,
				MIMEType: "text/plain",
			},
		},
		{
			path:   "/hardlink-1",
			exists: true,
			expected: file.Metadata{
				Mode:            0644,
				Type:            "HardLink",
				LinkDestination: "file-1.txt",
				UserID:          1,
				GroupID:         2,
				MIMEType:        "",
			},
		},
		{
			path:   "/symlink-1",
			exists: true,
			expected: file.Metadata{
				Mode:            0777 | os.ModeSymlink,
				Type:            "SymbolicLink",
				LinkDestination: "file-1.txt",
				UserID:          0,
				GroupID:         0,
				MIMEType:        "",
			},
		},
		{
			path:   "/char-device-1",
			exists: true,
			expected: file.Metadata{
				Mode:     0644 | os.ModeDevice | os.ModeCharDevice,
				Type:     "CharacterDevice",
				UserID:   0,
				GroupID:  0,
				MIMEType: "",
			},
		},
		{
			path:   "/block-device-1",
			exists: true,
			expected: file.Metadata{
				Mode:     0644 | os.ModeDevice,
				Type:     "BlockDevice",
				UserID:   0,
				GroupID:  0,
				MIMEType: "",
			},
		},
		{
			path:   "/fifo-1",
			exists: true,
			expected: file.Metadata{
				Mode:     0644 | os.ModeNamedPipe,
				Type:     "FIFONode",
				UserID:   0,
				GroupID:  0,
				MIMEType: "",
			},
		},
		{
			path:   "/bin",
			exists: true,
			expected: file.Metadata{
				Mode:     0755 | os.ModeDir,
				Type:     "Directory",
				UserID:   0,
				GroupID:  0,
				MIMEType: "",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			_, ref, err := img.SquashedTree().File(stereoscopeFile.Path(test.path))
			if err != nil {
				t.Fatalf("unable to get file: %+v", err)
			}

			l := file.NewLocationFromImage(test.path, *ref, img)

			assert.Equal(t, test.expected, actual[l.Coordinates], "mismatched metadata")

		})
	}

}
