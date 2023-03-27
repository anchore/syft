package pkg

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/source"
)

func TestRelationshipsEvidentBy(t *testing.T) {

	c := NewCatalog()

	simpleCoord := source.Coordinates{
		RealPath:     "/somewhere/real",
		FileSystemID: "abc",
	}
	simple := Package{
		Locations: source.NewLocationSet(source.NewLocationFromCoordinates(simpleCoord)),
	}
	simple.SetID()
	c.Add(simple)

	symlinkCoord := source.Coordinates{
		RealPath:     "/somewhere/real",
		FileSystemID: "def",
	}
	symlink := Package{
		Locations: source.NewLocationSet(source.NewLocationFromCoordinates(symlinkCoord)),
	}
	symlink.SetID()
	c.Add(symlink)

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
					From: simple,
					To:   simpleCoord,
					Type: artifact.EvidentByRelationship,
				},
				{
					From: symlink,
					To:   symlinkCoord,
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
				require.Equal(t, tt.want[i].From.ID(), actual[i].From.ID())
				require.Equal(t, tt.want[i].To.ID(), actual[i].To.ID())
				require.Equal(t, tt.want[i].Type, actual[i].Type)
			}
		})
	}
}
