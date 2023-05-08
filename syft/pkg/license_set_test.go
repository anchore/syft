package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/source"
)

func TestLicenseSet_Add(t *testing.T) {
	tests := []struct {
		name     string
		licenses []License
		want     []License
	}{
		{
			name: "add one simple license",
			licenses: []License{
				NewLicense("MIT"),
			},
			want: []License{
				NewLicense("MIT"),
			},
		},
		{
			name: "keep multiple licenses sorted",
			licenses: []License{
				NewLicense("MIT"),
				NewLicense("Apache-2.0"),
			},
			want: []License{
				NewLicense("Apache-2.0"),
				NewLicense("MIT"),
			},
		},
		{
			name: "duplicate licenses with locations",
			licenses: []License{
				NewLicenseFromLocation("MIT", source.NewLocationFromCoordinates(source.Coordinates{RealPath: "/place", FileSystemID: "1"})),
				NewLicenseFromLocation("MIT", source.NewLocationFromCoordinates(source.Coordinates{RealPath: "/place", FileSystemID: "1"})),
				NewLicenseFromLocation("MIT", source.NewLocationFromCoordinates(source.Coordinates{RealPath: "/place", FileSystemID: "2"})),
			},
			want: []License{
				NewLicenseFromLocation("MIT", source.NewLocationFromCoordinates(source.Coordinates{RealPath: "/place", FileSystemID: "2"})),
				NewLicenseFromLocation("MIT", source.NewLocationFromCoordinates(source.Coordinates{RealPath: "/place", FileSystemID: "1"})),
			},
		},
		{
			name: "same licenses with different locations",
			licenses: []License{
				NewLicense("MIT"),
				NewLicenseFromLocation("MIT", source.NewLocationFromCoordinates(source.Coordinates{RealPath: "/place", FileSystemID: "2"})),
				NewLicenseFromLocation("MIT", source.NewLocationFromCoordinates(source.Coordinates{RealPath: "/place", FileSystemID: "1"})),
			},
			want: []License{
				NewLicenseFromLocation("MIT", source.NewLocationFromCoordinates(source.Coordinates{RealPath: "/place", FileSystemID: "1"})),
				NewLicenseFromLocation("MIT", source.NewLocationFromCoordinates(source.Coordinates{RealPath: "/place", FileSystemID: "2"})),
				NewLicense("MIT"),
			},
		},
		{
			name: "same license from different sources",
			licenses: []License{
				NewLicense("MIT"),
				NewLicenseFromLocation("MIT", source.NewLocation("/place")),
				NewLicenseFromURL("MIT", "https://example.com"),
			},
			want: []License{
				NewLicenseFromURL("MIT", "https://example.com"),
				NewLicenseFromLocation("MIT", source.NewLocation("/place")),
				NewLicense("MIT"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewLicenseSet()
			s.Add(tt.licenses...)
			testMe := s.ToSlice()
			assert.Equal(t, tt.want, testMe)
		})
	}
}
