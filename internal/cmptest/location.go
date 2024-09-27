package cmptest

import (
	"github.com/google/go-cmp/cmp"

	"github.com/anchore/syft/syft/file"
)

type LocationComparer func(x, y file.Location) bool

func DefaultLocationComparer(x, y file.Location) bool {
	return cmp.Equal(x.Coordinates, y.Coordinates) && cmp.Equal(x.AccessPath, y.AccessPath)
}
