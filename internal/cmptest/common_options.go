package cmptest

import (
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func DefaultOptions() []cmp.Option {
	return BuildOptions(nil, nil)
}

func DefaultIgnoreLocationLayerOptions() []cmp.Option {
	return BuildOptions(LicenseComparerWithoutLocationLayer, LocationComparerWithoutLayer)
}

func BuildOptions(licenseCmp LicenseComparer, locationCmp LocationComparer) []cmp.Option {
	if licenseCmp == nil {
		licenseCmp = DefaultLicenseComparer
	}

	if locationCmp == nil {
		locationCmp = DefaultLocationComparer
	}

	return []cmp.Option{
		cmpopts.IgnoreFields(pkg.Package{}, "id"), // note: ID is not deterministic for test purposes
		cmpopts.SortSlices(pkg.Less),
		cmpopts.SortSlices(DefaultRelationshipComparer),
		cmp.Comparer(buildSetComparer[file.Location, file.LocationSet](locationCmp)),
		cmp.Comparer(buildSetComparer[pkg.License, pkg.LicenseSet](licenseCmp)),
		cmp.Comparer(locationCmp),
		cmp.Comparer(licenseCmp),
	}
}
