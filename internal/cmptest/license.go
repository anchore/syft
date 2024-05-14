package cmptest

import (
	"github.com/google/go-cmp/cmp"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

type LicenseComparer func(x, y pkg.License) bool

func DefaultLicenseComparer(x, y pkg.License) bool {
	return cmp.Equal(x, y, cmp.Comparer(DefaultLocationComparer), cmp.Comparer(
		func(x, y file.LocationSet) bool {
			xs := x.ToSlice()
			ys := y.ToSlice()
			if len(xs) != len(ys) {
				return false
			}
			for i, xe := range xs {
				ye := ys[i]
				if !DefaultLocationComparer(xe, ye) {
					return false
				}
			}
			return true
		},
	))
}
