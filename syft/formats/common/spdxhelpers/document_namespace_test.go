package spdxhelpers

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/internal"
	"github.com/anchore/syft/syft/source"
)

func Test_documentNamespace(t *testing.T) {
	allSources := strset.New()
	for _, s := range internal.AllSourceMetadataReflectTypes() {
		allSources.Add(s.Name())
	}
	testedSources := strset.New()

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
				Metadata: source.StereoscopeImageSourceMetadata{
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
				Metadata: source.DirectorySourceMetadata{
					Path: "some/path/to/place",
				},
			},
			expected: "https://anchore.com/syft/dir/my-name-",
		},
		{
			name:      "file",
			inputName: "my-name",
			src: source.Description{
				Metadata: source.FileSourceMetadata{
					Path: "some/path/to/place",
				},
			},
			expected: "https://anchore.com/syft/file/my-name-",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := DocumentNamespace(test.inputName, test.src)
			// note: since the namespace ends with a UUID we check the prefix
			assert.True(t, strings.HasPrefix(actual, test.expected), fmt.Sprintf("actual namespace %q", actual))

			// track each scheme tested (passed or not)
			testedSources.Add(reflect.TypeOf(test.src.Metadata).Name())
		})
	}

	// assert all possible schemes were under test
	assert.ElementsMatch(t, allSources.List(), testedSources.List(), "not all source.Schemes are under test")
}
