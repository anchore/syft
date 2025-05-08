package relationship

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func TestRelationshipsEvidentBy(t *testing.T) {

	c := pkg.NewCollection()

	coordA := file.Coordinates{
		RealPath:     "/somewhere/real",
		FileSystemID: "abc",
	}
	coordC := file.Coordinates{
		RealPath:     "/somewhere/real",
		FileSystemID: "abc",
	}
	coordD := file.Coordinates{
		RealPath:     "/somewhere/real",
		FileSystemID: "abc",
	}
	pkgA := pkg.Package{
		Locations: file.NewLocationSet(
			// added!
			file.NewLocationFromCoordinates(coordA).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			// ignored...
			file.NewLocationFromCoordinates(coordC).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation),
			file.NewLocationFromCoordinates(coordD),
		),
	}
	pkgA.SetID()
	c.Add(pkgA)

	coordB := file.Coordinates{
		RealPath:     "/somewhere-else/real",
		FileSystemID: "def",
	}
	pkgB := pkg.Package{
		Locations: file.NewLocationSet(
			// added!
			file.NewLocationFromCoordinates(coordB).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
	}
	pkgB.SetID()
	c.Add(pkgB)

	tests := []struct {
		name    string
		catalog *pkg.Collection
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
			actual := EvidentBy(tt.catalog)
			require.Len(t, actual, len(tt.want))
			for i := range actual {
				assert.Equal(t, tt.want[i].From.ID(), actual[i].From.ID(), "from mismatch at index %d", i)
				assert.Equal(t, tt.want[i].To.ID(), actual[i].To.ID(), "to mismatch at index %d", i)
				assert.Equal(t, tt.want[i].Type, actual[i].Type, "type mismatch at index %d", i)
			}
		})
	}
}
