package syftjson

import (
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/formats/syftjson/model"
	"github.com/anchore/syft/syft/source"
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

func Test_toFileType(t *testing.T) {

	badType := file.Type(0x1337)
	var allTypesTested []file.Type
	tests := []struct {
		ty   file.Type
		name string
	}{
		{
			ty:   file.TypeRegular,
			name: "RegularFile",
		},
		{
			ty:   file.TypeDirectory,
			name: "Directory",
		},
		{
			ty:   file.TypeSymLink,
			name: "SymbolicLink",
		},
		{
			ty:   file.TypeHardLink,
			name: "HardLink",
		},
		{
			ty:   file.TypeSocket,
			name: "Socket",
		},
		{
			ty:   file.TypeCharacterDevice,
			name: "CharacterDevice",
		},
		{
			ty:   file.TypeBlockDevice,
			name: "BlockDevice",
		},
		{
			ty:   file.TypeFIFO,
			name: "FIFONode",
		},
		{
			ty:   file.TypeIrregular,
			name: "IrregularFile",
		},
		{
			ty:   badType,
			name: "Unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.name, toFileType(tt.ty), "toFileType(%v)", tt.ty)
			if tt.ty != badType {
				allTypesTested = append(allTypesTested, tt.ty)
			}
		})
	}

	assert.ElementsMatch(t, allTypesTested, file.AllTypes(), "not all file.Types are under test")
}
