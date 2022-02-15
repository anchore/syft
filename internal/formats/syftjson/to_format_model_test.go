package syftjson

import (
	"testing"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/formats/syftjson/model"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_toSourceModel(t *testing.T) {
	allSchemes := strset.New()
	for _, s := range source.AllSchemes {
		allSchemes.Add(string(s))
	}
	testedSchemes := strset.New()

	tests := []struct {
		name     string
		src      source.Metadata
		expected model.Source
	}{
		{
			name: "directory",
			src: source.Metadata{
				Scheme: source.DirectoryScheme,
				Path:   "some/path",
			},
			expected: model.Source{
				Type:   "directory",
				Target: "some/path",
			},
		},
		{
			name: "file",
			src: source.Metadata{
				Scheme: source.FileScheme,
				Path:   "some/path",
			},
			expected: model.Source{
				Type:   "file",
				Target: "some/path",
			},
		},
		{
			name: "image",
			src: source.Metadata{
				Scheme: source.ImageScheme,
				ImageMetadata: source.ImageMetadata{
					UserInput:      "user-input",
					ID:             "id...",
					ManifestDigest: "digest...",
					MediaType:      "type...",
				},
			},
			expected: model.Source{
				Type: "image",
				Target: source.ImageMetadata{
					UserInput:      "user-input",
					ID:             "id...",
					ManifestDigest: "digest...",
					MediaType:      "type...",
					RepoDigests:    []string{},
					Tags:           []string{},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// track each scheme tested (passed or not)
			testedSchemes.Add(string(test.src.Scheme))

			// assert the model transformation is correct
			actual, err := toSourceModel(test.src)
			require.NoError(t, err)
			assert.Equal(t, test.expected, actual)
		})
	}

	// assert all possible schemes were under test
	assert.ElementsMatch(t, allSchemes.List(), testedSchemes.List(), "not all source.Schemes are under test")
}
