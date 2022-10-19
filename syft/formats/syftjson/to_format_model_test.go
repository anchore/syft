package syftjson

import (
	"strings"
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/formats/syftjson/model"
	"github.com/anchore/syft/syft/source"
)

func Test_SyftJsonID_Compatibility(t *testing.T) {
	jsonMajorVersion := strings.Split(internal.JSONSchemaVersion, ".")[0]
	syftJsonIDVersion := strings.Split(string(ID), "-")[1]
	assert.Equal(t, jsonMajorVersion, syftJsonIDVersion)
}

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
				ID:     "test-id",
				Scheme: source.DirectoryScheme,
				Path:   "some/path",
			},
			expected: model.Source{
				ID:     "test-id",
				Type:   "directory",
				Target: "some/path",
			},
		},
		{
			name: "file",
			src: source.Metadata{
				ID:     "test-id",
				Scheme: source.FileScheme,
				Path:   "some/path",
			},
			expected: model.Source{
				ID:     "test-id",
				Type:   "file",
				Target: "some/path",
			},
		},
		{
			name: "image",
			src: source.Metadata{
				ID:     "test-id",
				Scheme: source.ImageScheme,
				ImageMetadata: source.ImageMetadata{
					UserInput:      "user-input",
					ID:             "id...",
					ManifestDigest: "digest...",
					MediaType:      "type...",
				},
			},
			expected: model.Source{
				ID:   "test-id",
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
