package pkgtest

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func AssertPackagesEqual(t testing.TB, expected, actual []pkg.Package) {
	if diff := cmp.Diff(expected, actual,
		cmpopts.IgnoreFields(pkg.Package{}, "id"), // note: ID is not deterministic for test purposes
		cmp.Comparer(
			func(x, y source.LocationSet) bool {
				xs := x.ToSlice()
				ys := y.ToSlice()

				if len(xs) != len(ys) {
					return false
				}
				for i, xe := range xs {
					ye := ys[i]
					if !(cmp.Equal(xe.Coordinates, ye.Coordinates) && cmp.Equal(xe.VirtualPath, ye.VirtualPath)) {
						return false
					}
				}

				return true
			},
		),
	); diff != "" {
		t.Errorf("unexpected packages from parsing (-expected +actual)\n%s", diff)
	}
}
