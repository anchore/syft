package spdxhelpers

import (
	"fmt"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/source"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
)

func Test_DocumentName(t *testing.T) {
	allSchemes := strset.New()
	for _, s := range source.AllSchemes {
		allSchemes.Add(string(s))
	}
	testedSchemes := strset.New()

	tests := []struct {
		name        string
		inputName   string
		srcMetadata source.Metadata
		expected    string
	}{
		{
			name:      "image",
			inputName: "my-name",
			srcMetadata: source.Metadata{
				Scheme: source.ImageScheme,
				ImageMetadata: source.ImageMetadata{
					UserInput:      "image-repo/name:tag",
					ID:             "id",
					ManifestDigest: "digest",
				},
			},
			expected: "image-repo/name-tag",
		},
		{
			name:      "directory",
			inputName: "my-name",
			srcMetadata: source.Metadata{
				Scheme: source.DirectoryScheme,
				Path:   "some/path/to/place",
			},
			expected: "some/path/to/place",
		},
		{
			name:      "file",
			inputName: "my-name",
			srcMetadata: source.Metadata{
				Scheme: source.FileScheme,
				Path:   "some/path/to/place",
			},
			expected: "some/path/to/place",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := DocumentName(test.srcMetadata)
			assert.True(t, strings.HasPrefix(actual, test.expected), fmt.Sprintf("actual name %q", actual))

			// track each scheme tested (passed or not)
			testedSchemes.Add(string(test.srcMetadata.Scheme))
		})
	}

	// assert all possible schemes were under test
	assert.ElementsMatch(t, allSchemes.List(), testedSchemes.List(), "not all source.Schemes are under test")
}
