package pkg

import (
	"context"
	"os"
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
			name:     "add one simple license",
			licenses: NewLicenseBuilder().WithValues("MIT").Build(context.TODO()).ToSlice(),
			want:     NewLicenseBuilder().WithValues("MIT").Build(context.TODO()).ToSlice(),
		},
		{
			name: "add multiple simple licenses",
			licenses: NewLicenseBuilder().WithValues("MIT", "MIT", "Apache-2.0").
				Build(context.Background()).ToSlice(),
			want: NewLicenseBuilder().WithValues("MIT", "Apache-2.0").
				Build(context.Background()).ToSlice(),
		},
		{
			name:     "attempt to add a license with no name",
			licenses: NewLicenseBuilder().WithValues("").Build(context.Background()).ToSlice(),
			want:     nil,
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
			licenses: NewLicenseBuilder().WithCandidates(
				[]LicenseCandidate{
					{Value: "MIT", Type: license.Concluded},
					{Value: "MIT", Type: license.Declared},
					{Value: "MIT", Type: license.Declared, Locations: []file.Location{file.NewLocation("/place")}},
				}...).Build(context.TODO()).ToSlice(),
			want: []License{
				{SPDXExpression: "MIT", Value: "MIT", Type: license.Concluded},
				{SPDXExpression: "MIT", Value: "MIT", Type: license.Declared, Locations: file.NewLocationSet(file.NewLocation("/place"))},
			},
		},
		{
			name: "licenses that are unknown with different contents can exist in the same set",
			licenses: []License{
				NewLicense(readFileAsString("../../internal/licenses/test-fixtures/nvidia-software-and-cuda-supplement")),
				NewLicense(readFileAsString("../../internal/licenses/test-fixtures/apache-license-2.0")),
			},
			want: []License{
				{
					Contents: readFileAsString("../../internal/licenses/test-fixtures/apache-license-2.0"),
					Type:     license.Declared,
				},
				{
					Contents: readFileAsString("../../internal/licenses/test-fixtures/nvidia-software-and-cuda-supplement"),
					Type:     license.Declared,
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

func readFileAsString(filepath string) string {
	data, err := os.ReadFile(filepath)
	if err != nil {
		panic(err)
	}
	return string(data)
}
