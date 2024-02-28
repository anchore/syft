package helpers

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/internal/sourcemetadata"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func Test_documentNamespace(t *testing.T) {
	tracker := sourcemetadata.NewCompletionTester(t)

	tests := []struct {
		name      string
		inputName string
		src       source.Description
		expected  string
	}{
		{
			name:      "image",
			inputName: "my-name",
			src: source.Description{
				Metadata: source.ImageMetadata{
					UserInput:      "image-repo/name:tag",
					ID:             "id",
					ManifestDigest: "digest",
				},
			},
			expected: "https://anchore.com/syft/image/my-name-",
		},
		{
			name:      "directory",
			inputName: "my-name",
			src: source.Description{
				Metadata: source.DirectoryMetadata{
					Path: "some/path/to/place",
				},
			},
			expected: "https://anchore.com/syft/dir/my-name-",
		},
		{
			name:      "file",
			inputName: "my-name",
			src: source.Description{
				Metadata: source.FileMetadata{
					Path: "some/path/to/place",
				},
			},
			expected: "https://anchore.com/syft/file/my-name-",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := DocumentNamespace(test.inputName, test.src, sbom.Descriptor{
				Name: "syft",
			})

			// note: since the namespace ends with a UUID we check the prefix
			assert.True(t, strings.HasPrefix(actual, test.expected), fmt.Sprintf("expected prefix: '%s' got: '%s'", test.expected, actual))

			// track each scheme tested (passed or not)
			tracker.Tested(t, test.src.Metadata)
		})
	}
}
