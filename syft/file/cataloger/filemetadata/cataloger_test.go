package filemetadata

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

func TestFileMetadataCataloger(t *testing.T) {
	testImage := "image-file-type-mix"

	img := imagetest.GetFixtureImage(t, "docker-archive", testImage)

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
				Path:     "/file-1.txt",
				Mode:     0644,
				Type:     stereoscopeFile.TypeRegular,
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
				Path:            "/hardlink-1",
				Mode:            0644,
				Type:            stereoscopeFile.TypeHardLink,
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
				Path:            "/symlink-1",
				Mode:            0777 | os.ModeSymlink,
				Type:            stereoscopeFile.TypeSymLink,
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
				Path:     "/char-device-1",
				Mode:     0644 | os.ModeDevice | os.ModeCharDevice,
				Type:     stereoscopeFile.TypeCharacterDevice,
				UserID:   0,
				GroupID:  0,
				MIMEType: "",
			},
		},
		{
			path:   "/block-device-1",
			exists: true,
			expected: file.Metadata{
				Path:     "/block-device-1",
				Mode:     0644 | os.ModeDevice,
				Type:     stereoscopeFile.TypeBlockDevice,
				UserID:   0,
				GroupID:  0,
				MIMEType: "",
			},
		},
		{
			path:   "/fifo-1",
			exists: true,
			expected: file.Metadata{
				Path:     "/fifo-1",
				Mode:     0644 | os.ModeNamedPipe,
				Type:     stereoscopeFile.TypeFIFO,
				UserID:   0,
				GroupID:  0,
				MIMEType: "",
			},
		},
		{
			path:   "/bin",
			exists: true,
			expected: file.Metadata{
				Path:     "/bin",
				Mode:     0755 | os.ModeDir,
				Type:     stereoscopeFile.TypeDirectory,
				UserID:   0,
				GroupID:  0,
				MIMEType: "",
				IsDir:    true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			_, ref, err := img.SquashedTree().File(stereoscopeFile.Path(test.path))
			require.NoError(t, err)

			l := file.NewLocationFromImage(test.path, *ref.Reference, img)

			defaultDate := time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
			if _, ok := actual[l.Coordinates]; ok {
				redact := actual[l.Coordinates]
				assert.NotEqual(t, defaultDate, redact.ModTime, "expected mod time to be set")
				assert.Equal(t, defaultDate, redact.AccessTime, "expected access time to be unset")
				assert.Equal(t, defaultDate, redact.ChangeTime, "expected change time to be unset")
				redact.ModTime = time.Time{}
				actual[l.Coordinates] = redact
			}

			assert.Equal(t, test.expected, actual[l.Coordinates], "mismatched metadata")

		})
	}

}
