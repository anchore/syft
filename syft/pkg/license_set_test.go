package pkg

import (
	"context"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
)

func TestLicenseSet_Add(t *testing.T) {
	scanner, err := licenses.NewDefaultScanner()
	require.NoError(t, err)
	ctx := licenses.SetContextLicenseScanner(context.Background(), scanner)
	tests := []struct {
		name     string
		licenses []License
		want     []License
	}{
		{
			name: "add one simple license",
			licenses: []License{
				NewLicenseWithContext(ctx, "MIT"),
			},
			want: []License{
				NewLicenseWithContext(ctx, "MIT"),
			},
		},
		{
			name: "add multiple simple licenses",
			licenses: []License{
				NewLicenseWithContext(ctx, "MIT"),
				NewLicenseWithContext(ctx, "MIT"),
				NewLicenseWithContext(ctx, "Apache-2.0"),
			},
			want: []License{
				NewLicenseWithContext(ctx, "Apache-2.0"),
				NewLicenseWithContext(ctx, "MIT"),
			},
		},
		{
			name: "attempt to add a license with no name",
			licenses: []License{
				NewLicenseWithContext(ctx, ""),
			},
			want: []License{},
		},
		{
			name: "keep multiple licenses sorted",
			licenses: []License{
				NewLicenseWithContext(ctx, "MIT"),
				NewLicenseWithContext(ctx, "Apache-2.0"),
			},
			want: []License{
				NewLicenseWithContext(ctx, "Apache-2.0"),
				NewLicenseWithContext(ctx, "MIT"),
			},
		},
		{
			name: "deduplicate licenses with locations",
			licenses: []License{
				NewLicenseFromLocationsWithContext(ctx, "MIT", file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/place", FileSystemID: "1"})),
				NewLicenseFromLocationsWithContext(ctx, "MIT", file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/place", FileSystemID: "1"})),
				NewLicenseFromLocationsWithContext(ctx, "MIT", file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/place", FileSystemID: "2"})),
			},
			want: []License{
				NewLicenseFromLocationsWithContext(
					ctx,
					"MIT",
					file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/place", FileSystemID: "1"}),
					file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/place", FileSystemID: "2"}),
				),
			},
		},
		{
			name: "same licenses with different locations",
			licenses: []License{
				NewLicenseWithContext(ctx, "MIT"),
				NewLicenseFromLocationsWithContext(ctx, "MIT", file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/place", FileSystemID: "2"})),
				NewLicenseFromLocationsWithContext(ctx, "MIT", file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/place", FileSystemID: "1"})),
			},
			want: []License{
				NewLicenseFromLocationsWithContext(
					ctx,
					"MIT",
					file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/place", FileSystemID: "1"}),
					file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/place", FileSystemID: "2"}),
				),
			},
		},
		{
			name: "same license from different sources",
			licenses: []License{
				NewLicenseWithContext(ctx, "MIT"),
				NewLicenseFromLocationsWithContext(ctx, "MIT", file.NewLocation("/place")),
				NewLicenseFromURLsWithContext(ctx, "MIT", "https://example.com"),
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
				NewLicenseFromTypeWithContext(ctx, "MIT", license.Concluded),
				NewLicenseFromTypeWithContext(ctx, "MIT", license.Declared),
				NewLicenseFromLocationsWithContext(ctx, "MIT", file.NewLocation("/place")),
				NewLicenseFromURLsWithContext(ctx, "MIT", "https://example.com"),
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
		{
			name: "licenses that are unknown with different contents can exist in the same set",
			licenses: []License{
				NewLicenseWithContext(ctx, readFileAsString("../../internal/licenses/test-fixtures/nvidia-software-and-cuda-supplement")),
				NewLicenseWithContext(ctx, readFileAsString("../../internal/licenses/test-fixtures/apache-license-2.0")),
			},
			want: []License{
				{
					SPDXExpression: "Apache-2.0",
					Value:          "Apache-2.0",
					Type:           license.Declared,
					Contents:       readFileAsString("../../internal/licenses/test-fixtures/apache-license-2.0"),
					Locations:      file.NewLocationSet(),
				},
				{
					Value:    "sha256:eebcea3ab1d1a28e671de90119ffcfb35fe86951e4af1b17af52b7a82fcf7d0a",
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
