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
			name: "add multiple simple licenses",
			licenses: []License{
				NewLicense("MIT"),
				NewLicense("MIT"),
				NewLicense("Apache-2.0"),
			},
			want: []License{
				NewLicense("Apache-2.0"),
				NewLicense("MIT"),
			},
		},
		{
			name: "attempt to add a license with no name",
			licenses: []License{
				NewLicense(""),
			},
			want: nil,
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
				NewLicenseFromURLs("MIT", "https://example.com"),
			},
			want: []License{
				{
					Value:          "MIT",
					SPDXExpression: "MIT",
					Type:           license.Declared,
					URLs:           internal.NewStringSet("https://example.com"),
					Locations:      source.NewLocationSet(source.NewLocation("/place")),
				},
			},
		},
		{
			name: "different licenses from different sources with different types constitute two licenses",
			licenses: []License{
				NewLicenseFromType("MIT", license.Concluded),
				NewLicenseFromType("MIT", license.Declared),
				NewLicenseFromLocations("MIT", source.NewLocation("/place")),
				NewLicenseFromURLs("MIT", "https://example.com"),
			},
			want: []License{
				{
					Value:          "MIT",
					SPDXExpression: "MIT",
					Type:           license.Concluded,
					URLs:           internal.NewStringSet(),
					Locations:      source.NewLocationSet(),
				},
				{
					Value:          "MIT",
					SPDXExpression: "MIT",
					Type:           license.Declared,
					URLs:           internal.NewStringSet("https://example.com"),
					Locations:      source.NewLocationSet(source.NewLocation("/place")),
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
