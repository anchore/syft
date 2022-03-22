package syftjson

import (
	"testing"

	"github.com/anchore/syft/internal/formats/syftjson/model"
	"github.com/anchore/syft/syft/source"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
)

func Test_toSyftSourceData(t *testing.T) {
	allSchemes := strset.New()
	for _, s := range source.AllTypes {
		allSchemes.Add(string(s))
	}
	testedSchemes := strset.New()

	tests := []struct {
		name     string
		src      model.Source
		expected source.Metadata
	}{
		{
			name: "directory",
			expected: source.Metadata{
				Scheme: source.DirectoryType,
				Path:   "some/path",
			},
			src: model.Source{
				Type:   "directory",
				Target: "some/path",
			},
		},
		{
			name: "file",
			expected: source.Metadata{
				Scheme: source.FileType,
				Path:   "some/path",
			},
			src: model.Source{
				Type:   "file",
				Target: "some/path",
			},
		},
		{
			name: "image",
			expected: source.Metadata{
				Scheme: source.ImageType,
				ImageMetadata: source.ImageMetadata{
					UserInput:      "user-input",
					ID:             "id...",
					ManifestDigest: "digest...",
					MediaType:      "type...",
				},
			},
			src: model.Source{
				Type: "image",
				Target: source.ImageMetadata{
					UserInput:      "user-input",
					ID:             "id...",
					ManifestDigest: "digest...",
					MediaType:      "type...",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// assert the model transformation is correct
			actual := toSyftSourceData(test.src)
			assert.Equal(t, test.expected, *actual)

			// track each scheme tested (passed or not)
			testedSchemes.Add(string(test.expected.Scheme))
		})
	}

	// assert all possible schemes were under test
	assert.ElementsMatch(t, allSchemes.List(), testedSchemes.List(), "not all source.Schemes are under test")
}
