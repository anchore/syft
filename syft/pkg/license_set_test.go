package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/license"
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
			name: "deduplicate licenses with locations",
			licenses: []License{
				NewLicenseFromLocations("MIT", source.NewLocationFromCoordinates(source.Coordinates{RealPath: "/place", FileSystemID: "1"})),
				NewLicenseFromLocations("MIT", source.NewLocationFromCoordinates(source.Coordinates{RealPath: "/place", FileSystemID: "1"})),
				NewLicenseFromLocations("MIT", source.NewLocationFromCoordinates(source.Coordinates{RealPath: "/place", FileSystemID: "2"})),
			},
			want: []License{
				NewLicenseFromLocations(
					"MIT",
					source.NewLocationFromCoordinates(source.Coordinates{RealPath: "/place", FileSystemID: "1"}),
					source.NewLocationFromCoordinates(source.Coordinates{RealPath: "/place", FileSystemID: "2"}),
				),
			},
		},
		{
			name: "same licenses with different locations",
			licenses: []License{
				NewLicense("MIT"),
				NewLicenseFromLocations("MIT", source.NewLocationFromCoordinates(source.Coordinates{RealPath: "/place", FileSystemID: "2"})),
				NewLicenseFromLocations("MIT", source.NewLocationFromCoordinates(source.Coordinates{RealPath: "/place", FileSystemID: "1"})),
			},
			want: []License{
				NewLicenseFromLocations(
					"MIT",
					source.NewLocationFromCoordinates(source.Coordinates{RealPath: "/place", FileSystemID: "1"}),
					source.NewLocationFromCoordinates(source.Coordinates{RealPath: "/place", FileSystemID: "2"}),
				),
			},
		},
		{
			name: "same license from different sources",
			licenses: []License{
				NewLicense("MIT"),
				NewLicenseFromLocations("MIT", source.NewLocation("/place")),
				LicenseFromURLs("MIT", "https://example.com"),
			},
			want: []License{
				{
					Value:          "MIT",
					SPDXExpression: "MIT",
					Type:           license.Declared,
					URL:            internal.NewStringSet("https://example.com"),
					Location:       source.NewLocationSet(source.NewLocation("/place")),
				},
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
