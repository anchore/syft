package pkg

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
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
				NewLicenseFromLocations("MIT", file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/place", FileSystemID: "1"})),
				NewLicenseFromLocations("MIT", file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/place", FileSystemID: "1"})),
				NewLicenseFromLocations("MIT", file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/place", FileSystemID: "2"})),
			},
			want: []License{
				NewLicenseFromLocations(
					"MIT",
					file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/place", FileSystemID: "1"}),
					file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/place", FileSystemID: "2"}),
				),
			},
		},
		{
			name: "same licenses with different locations",
			licenses: []License{
				NewLicense("MIT"),
				NewLicenseFromLocations("MIT", file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/place", FileSystemID: "2"})),
				NewLicenseFromLocations("MIT", file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/place", FileSystemID: "1"})),
			},
			want: []License{
				NewLicenseFromLocations(
					"MIT",
					file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/place", FileSystemID: "1"}),
					file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/place", FileSystemID: "2"}),
				),
			},
		},
		{
			name: "same license from different sources",
			licenses: []License{
				NewLicense("MIT"),
				NewLicenseFromLocations("MIT", file.NewLocation("/place")),
				NewLicenseFromURLs("MIT", "https://example.com"),
			},
			want: []License{
				{
					Value:          "MIT",
					SPDXExpression: "MIT",
					Type:           license.Declared,
					URLs:           []string{"https://example.com"},
					Locations:      file.NewLocationSet(file.NewLocation("/place")),
				},
			},
		},
		{
			name: "different licenses from different sources with different types constitute two licenses",
			licenses: []License{
				NewLicenseFromType("MIT", license.Concluded),
				NewLicenseFromType("MIT", license.Declared),
				NewLicenseFromLocations("MIT", file.NewLocation("/place")),
				NewLicenseFromURLs("MIT", "https://example.com"),
			},
			want: []License{
				{
					Value:          "MIT",
					SPDXExpression: "MIT",
					Type:           license.Concluded,
					Locations:      file.NewLocationSet(),
				},
				{
					Value:          "MIT",
					SPDXExpression: "MIT",
					Type:           license.Declared,
					URLs:           []string{"https://example.com"},
					Locations:      file.NewLocationSet(file.NewLocation("/place")),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewLicenseSet()
			s.Add(tt.licenses...)
			testMe := s.ToSlice()
			if d := cmp.Diff(tt.want, testMe, cmp.Comparer(defaultLicenseComparer)); d != "" {
				t.Errorf("unexpected license set (-want +got):\n%s", d)
			}
		})
	}
}

func defaultLocationComparer(x, y file.Location) bool {
	return cmp.Equal(x.Coordinates, y.Coordinates) && cmp.Equal(x.AccessPath, y.AccessPath)
}

func defaultLicenseComparer(x, y License) bool {
	return cmp.Equal(x, y, cmp.Comparer(defaultLocationComparer), cmp.Comparer(
		func(x, y file.LocationSet) bool {
			xs := x.ToSlice()
			ys := y.ToSlice()
			if len(xs) != len(ys) {
				return false
			}
			for i, xe := range xs {
				ye := ys[i]
				if !defaultLocationComparer(xe, ye) {
					return false
				}
			}
			return true
		},
	))
}
