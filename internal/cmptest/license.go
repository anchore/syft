package cmptest

import (
	"github.com/google/go-cmp/cmp"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

type LicenseComparer func(x, y pkg.License) bool

func DefaultLicenseComparer(x, y pkg.License) bool {
	return cmp.Equal(
		x, y,
		cmp.Comparer(DefaultLocationComparer),
		cmp.Comparer(buildSetComparer[file.Location, file.LocationSet](DefaultLocationComparer, locationSorter)),
	)
}

func LicenseComparerWithoutLocationLayer(x, y pkg.License) bool {
	return cmp.Equal(
		x, y,
		cmp.Comparer(LocationComparerWithoutLayer),
		cmp.Comparer(buildSetComparer[file.Location, file.LocationSet](LocationComparerWithoutLayer, locationSorter)),
	)
}
