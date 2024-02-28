package file

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/stereoscope/pkg/file"
)

func TestLocation_ID(t *testing.T) {
	tests := []struct {
		name        string
		coordinates Coordinates
		virtualPath string
		ref         file.Reference
	}{
		{
			name: "coordinates should match location hash",
			coordinates: Coordinates{
				RealPath:     "path!",
				FileSystemID: "filesystem!",
			},
		},
		{
			name: "coordinates should match location hash (with extra fields)",
			coordinates: Coordinates{
				RealPath:     "path!",
				FileSystemID: "filesystem!",
			},
			virtualPath: "virtualPath!",
			ref: file.Reference{
				RealPath: "other-real-path!",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			l := Location{
				LocationData: LocationData{
					Coordinates: test.coordinates,
					AccessPath:  test.virtualPath,
					ref:         test.ref,
				},
			}
			assert.Equal(t, l.ID(), test.coordinates.ID())
		})
	}

}
