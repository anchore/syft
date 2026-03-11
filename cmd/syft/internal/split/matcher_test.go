package split

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg"
)

func TestMatchPackages(t *testing.T) {
	// create test packages
	pkgA := pkg.Package{
		Name:    "alpine-baselayout",
		Version: "3.2.0-r7",
		PURL:    "pkg:apk/alpine/alpine-baselayout@3.2.0-r7",
	}
	pkgA.SetID()

	pkgB := pkg.Package{
		Name:    "musl",
		Version: "1.2.2-r0",
		PURL:    "pkg:apk/alpine/musl@1.2.2-r0",
	}
	pkgB.SetID()

	pkgC := pkg.Package{
		Name:    "Musl", // different case
		Version: "2.0.0",
		PURL:    "pkg:apk/alpine/Musl@2.0.0",
	}
	pkgC.SetID()

	collection := pkg.NewCollection(pkgA, pkgB, pkgC)

	tests := []struct {
		name    string
		queries []string
		want    []pkg.Package
	}{
		{
			name:    "match by exact package ID",
			queries: []string{string(pkgA.ID())},
			want:    []pkg.Package{pkgA},
		},
		{
			name:    "match by exact PURL",
			queries: []string{"pkg:apk/alpine/musl@1.2.2-r0"},
			want:    []pkg.Package{pkgB},
		},
		{
			name:    "match by PURL prefix",
			queries: []string{"pkg:apk/alpine/musl"},
			want:    []pkg.Package{pkgB},
		},
		{
			name:    "match by case-insensitive name",
			queries: []string{"musl"},
			want:    []pkg.Package{pkgB, pkgC},
		},
		{
			name:    "match by name@version",
			queries: []string{"musl@1.2.2-r0"},
			want:    []pkg.Package{pkgB},
		},
		{
			name:    "multiple queries",
			queries: []string{"alpine-baselayout", "musl@1.2.2-r0"},
			want:    []pkg.Package{pkgA, pkgB},
		},
		{
			name:    "no match",
			queries: []string{"nonexistent"},
			want:    []pkg.Package{},
		},
		{
			name:    "empty queries",
			queries: []string{},
			want:    nil,
		},
		{
			name:    "nil collection returns nil",
			queries: []string{"musl"},
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			coll := collection
			if tt.name == "nil collection returns nil" {
				coll = nil
			}

			got := MatchPackages(coll, tt.queries)

			if tt.want == nil {
				require.Nil(t, got)
				return
			}

			require.Len(t, got, len(tt.want))

			if len(tt.want) == 0 {
				return
			}

			// sort both for comparison
			pkg.Sort(tt.want)

			// compare using cmp.Diff, ignoring unexported fields
			opts := []cmp.Option{
				cmpopts.IgnoreUnexported(pkg.Package{}),
				cmpopts.IgnoreFields(pkg.Package{}, "Locations", "Licenses", "CPEs"),
			}

			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("MatchPackages() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
