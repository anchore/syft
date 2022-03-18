package syftjson

import (
	"testing"

	"github.com/anchore/syft/internal/formats/syftjson/model"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/source"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
)

func Test_toSyftSourceData(t *testing.T) {
	allSchemes := strset.New()
	for _, s := range source.AllSchemes {
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
				Scheme: source.DirectoryScheme,
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
				Scheme: source.FileScheme,
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
				Scheme: source.ImageScheme,
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

func Test_idsHaveChanged(t *testing.T) {
	s, err := toSyftModel(model.Document{
		Source: model.Source{
			Type:   "file",
			Target: "some/path",
		},
		Artifacts: []model.Package{
			{
				PackageBasicData: model.PackageBasicData{
					ID:   "1",
					Name: "pkg-1",
				},
			},
			{
				PackageBasicData: model.PackageBasicData{
					ID:   "2",
					Name: "pkg-2",
				},
			},
		},
		ArtifactRelationships: []model.Relationship{
			{
				Parent: "1",
				Child:  "2",
				Type:   string(artifact.ContainsRelationship),
			},
		},
	})

	assert.NoError(t, err)
	assert.Len(t, s.Relationships, 1)

	r := s.Relationships[0]

	from := s.Artifacts.PackageCatalog.Package(r.From.ID())
	assert.NotNil(t, from)
	assert.Equal(t, "pkg-1", from.Name)

	to := s.Artifacts.PackageCatalog.Package(r.To.ID())
	assert.NotNil(t, to)
	assert.Equal(t, "pkg-2", to.Name)
}
