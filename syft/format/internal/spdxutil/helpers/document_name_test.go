package helpers

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/internal/sourcemetadata"
	"github.com/anchore/syft/syft/source"
)

func Test_DocumentName(t *testing.T) {

	tracker := sourcemetadata.NewCompletionTester(t)

	tests := []struct {
		name        string
		srcMetadata source.Description
		expected    string
	}{
		{
			name: "image",
			srcMetadata: source.Description{
				Metadata: source.ImageMetadata{
					UserInput:      "image-repo/name:tag",
					ID:             "id",
					ManifestDigest: "digest",
				},
			},
			expected: "image-repo/name:tag",
		},
		{
			name: "directory",
			srcMetadata: source.Description{
				Metadata: source.DirectoryMetadata{Path: "some/path/to/place"},
			},
			expected: "some/path/to/place",
		},
		{
			name: "file",
			srcMetadata: source.Description{
				Metadata: source.FileMetadata{Path: "some/path/to/place"},
			},
			expected: "some/path/to/place",
		},
		{
			name: "named",
			srcMetadata: source.Description{
				Name:     "some/name",
				Metadata: source.FileMetadata{Path: "some/path/to/place"},
			},
			expected: "some/name",
		},
		{
			name: "application",
			srcMetadata: source.Description{
				Name: "application",
				Metadata: source.ApplicationMetadata{
					UnknownMetadata: source.UnknownMetadata{
						Group: "org.anchore",
					},
				},
			},
			expected: "application",
		},
		{
			name: "library",
			srcMetadata: source.Description{
				Name: "library",
				Metadata: source.LibraryMetadata{
					UnknownMetadata: source.UnknownMetadata{
						Group: "org.anchore",
					},
				},
			},
			expected: "library",
		},
		{
			name: "framework",
			srcMetadata: source.Description{
				Name: "framework",
				Metadata: source.FrameworkMetadata{
					UnknownMetadata: source.UnknownMetadata{
						Group: "org.anchore",
					},
				},
			},
			expected: "framework",
		},
		{
			name: "os",
			srcMetadata: source.Description{
				Name: "os",
				Metadata: source.OSMetadata{
					UnknownMetadata: source.UnknownMetadata{
						Group: "org.anchore",
					},
				},
			},
			expected: "os",
		},
		{
			name: "platform",
			srcMetadata: source.Description{
				Name: "platform",
				Metadata: source.PlatformMetadata{
					UnknownMetadata: source.UnknownMetadata{
						Group: "org.anchore",
					},
				},
			},
			expected: "platform",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := DocumentName(test.srcMetadata)
			assert.True(t, strings.HasPrefix(actual, test.expected), fmt.Sprintf("actual name %q", actual))

			// track each scheme tested (passed or not)
			tracker.Tested(t, test.srcMetadata.Metadata)
		})
	}
}
