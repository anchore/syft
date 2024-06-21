package cmptest

import (
	"slices"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func DefaultCommonOptions() []cmp.Option {
	return CommonOptions(nil, nil)
}

func CommonOptions(licenseCmp LicenseComparer, locationCmp LocationComparer) []cmp.Option {
	if licenseCmp == nil {
		licenseCmp = DefaultLicenseComparer
	}

	if locationCmp == nil {
		locationCmp = DefaultLocationComparer
	}

	return []cmp.Option{
		cmpopts.IgnoreFields(pkg.Package{}, "id"), // note: ID is not deterministic for test purposes
		cmpopts.SortSlices(pkg.Less),
		cmp.Comparer(func(x, y []artifact.Relationship) bool {
			//copy here, because we shouldn't mutate the input in any way!
			cpyX := make([]artifact.Relationship, len(x))
			copy(cpyX, x)
			cpyY := make([]artifact.Relationship, len(y))
			copy(cpyY, x)
			slices.SortStableFunc(cpyX, DefaultRelationshipComparer)
			slices.SortStableFunc(cpyY, DefaultRelationshipComparer)
			return slices.CompareFunc(cpyX, cpyY, DefaultRelationshipComparer) == 0
		}),
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
			locationCmp,
		),
		cmp.Comparer(
			licenseCmp,
		),
	}
}
