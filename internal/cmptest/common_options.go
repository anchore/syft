package cmptest

import (
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func DefaultCommonOptions() []cmp.Option {
	return CommonOptions(nil, nil, nil)
}

//nolint:funlen
func CommonOptions(licenseCmp LicenseComparer, locationCmp LocationComparer, copyrightCmp CopyrightComparer) []cmp.Option {
	if licenseCmp == nil {
		licenseCmp = DefaultLicenseComparer
	}

	if locationCmp == nil {
		locationCmp = DefaultLocationComparer
	}

	if copyrightCmp == nil {
		copyrightCmp = DefaultCopyrightComparer
	}

	return []cmp.Option{
		cmpopts.IgnoreFields(pkg.Package{}, "id"), // note: ID is not deterministic for test purposes
		cmpopts.SortSlices(pkg.Less),
		cmpopts.SortSlices(DefaultRelationshipComparer),
		cmp.Comparer(
			func(x, y file.LocationSet) bool {
				xs := x.ToSlice()
				ys := y.ToSlice()

				if len(xs) != len(ys) {
					return false
				}
				for i, xe := range xs {
					ye := ys[i]
					if !locationCmp(xe, ye) {
						return false
					}
				}

				return true
			},
		),
		cmp.Comparer(
			func(x, y pkg.LicenseSet) bool {
				xs := x.ToSlice()
				ys := y.ToSlice()

				if len(xs) != len(ys) {
					return false
				}
				for i, xe := range xs {
					ye := ys[i]
					if !licenseCmp(xe, ye) {
						return false
					}
				}

				return true
			},
		),
		cmp.Comparer(
			func(x, y pkg.CopyrightsSet) bool {
				xs := x.ToSlice()
				ys := y.ToSlice()

				if len(xs) != len(ys) {
					return false
				}
				for i, xe := range xs {
					ye := ys[i]
					if !copyrightCmp(xe, ye) {
						return false
					}
				}
				return true
			},
		),
		cmp.Comparer(
			locationCmp,
		),
		cmp.Comparer(
			licenseCmp,
		),
		cmp.Comparer(
			copyrightCmp,
		),
	}
}
