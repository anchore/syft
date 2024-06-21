package cmptest

import (
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"slices"
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
		cmpopts.AcyclicTransformer("SortRelationships", func(s []artifact.Relationship) []artifact.Relationship {
			//copy here, because we shouldn't mutate the input in any way!
			cpy := make([]artifact.Relationship, len(s))
			copy(cpy, s)
			slices.SortStableFunc(cpy, DefaultRelationshipComparer)
			return cpy
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
