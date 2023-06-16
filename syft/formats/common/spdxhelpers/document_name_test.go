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

func Test_DocumentName(t *testing.T) {
	allSchemes := strset.New()
	for _, s := range internal.AllSourceMetadataReflectTypes() {
		allSchemes.Add(s.Name())
	}
	testedSchemes := strset.New()

	tests := []struct {
		name        string
		inputName   string
		srcMetadata source.Description
		expected    string
	}{
		{
			name:      "image",
			inputName: "my-name",
			srcMetadata: source.Description{
				Metadata: source.StereoscopeImageSourceMetadata{
					UserInput:      "image-repo/name:tag",
					ID:             "id",
					ManifestDigest: "digest",
				},
			},
			expected: "image-repo/name:tag",
		},
		{
			name:      "directory",
			inputName: "my-name",
			srcMetadata: source.Description{
				Metadata: source.DirectorySourceMetadata{Path: "some/path/to/place"},
			},
			expected: "some/path/to/place",
		},
		{
			name:      "file",
			inputName: "my-name",
			srcMetadata: source.Description{
				Metadata: source.FileSourceMetadata{Path: "some/path/to/place"},
			},
			expected: "some/path/to/place",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := DocumentName(test.srcMetadata)
			assert.True(t, strings.HasPrefix(actual, test.expected), fmt.Sprintf("actual name %q", actual))

			// track each scheme tested (passed or not)
			testedSchemes.Add(reflect.TypeOf(test.srcMetadata.Metadata).Name())
		})
	}

	// assert all possible schemes were under test
	assert.ElementsMatch(t, allSchemes.List(), testedSchemes.List(), "not all source.*Metadata are under test")
}
