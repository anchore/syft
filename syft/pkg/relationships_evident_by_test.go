package pkg

import (
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/source"
)

func TestRelationshipsEvidentBy(t *testing.T) {

	c := NewCatalog()

	coordA := source.Coordinates{
		RealPath:     "/somewhere/real",
		FileSystemID: "abc",
	}
	coordC := source.Coordinates{
		RealPath:     "/somewhere/real",
		FileSystemID: "abc",
	}
	coordD := source.Coordinates{
		RealPath:     "/somewhere/real",
		FileSystemID: "abc",
	}
	pkgA := Package{
		Locations: source.NewLocationSet(
			// added!
			source.NewLocationFromCoordinates(coordA).WithAnnotation(EvidenceAnnotationKey, PrimaryEvidenceAnnotation),
			// ignored...
			source.NewLocationFromCoordinates(coordC).WithAnnotation(EvidenceAnnotationKey, SupportingEvidenceAnnotation),
			source.NewLocationFromCoordinates(coordD),
		),
	}
	pkgA.SetID()
	c.Add(pkgA)

	coordB := source.Coordinates{
		RealPath:     "/somewhere-else/real",
		FileSystemID: "def",
	}
	pkgB := Package{
		Locations: source.NewLocationSet(
			// added!
			source.NewLocationFromCoordinates(coordB).WithAnnotation(EvidenceAnnotationKey, PrimaryEvidenceAnnotation),
		),
	}
	pkgB.SetID()
	c.Add(pkgB)

	tests := []struct {
		name    string
		catalog *Catalog
		want    []artifact.Relationship
	}{
		{
			name:    "go case",
			catalog: c,
			want: []artifact.Relationship{
				{
					From: pkgB,
					To:   coordB,
					Type: artifact.EvidentByRelationship,
				},
				{
					From: pkgA,
					To:   coordA,
					Type: artifact.EvidentByRelationship,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := RelationshipsEvidentBy(tt.catalog)
			require.Len(t, actual, len(tt.want))
			for i := range actual {
				assert.Equal(t, tt.want[i].From.ID(), actual[i].From.ID(), "from mismatch at index %d", i)
				assert.Equal(t, tt.want[i].To.ID(), actual[i].To.ID(), "to mismatch at index %d", i)
				assert.Equal(t, tt.want[i].Type, actual[i].Type, "type mismatch at index %d", i)
			}
		})
	}
}
