package cmptest

import (
	"github.com/google/go-cmp/cmp"

	"github.com/anchore/syft/syft/pkg"
)

type CopyrightComparer func(x, y pkg.Copyright) bool

func DefaultCopyrightComparer(x, y pkg.Copyright) bool {
	return cmp.Equal(x, y, cmp.Comparer(
		func(x, y string) bool {
			return x == y
		},
	))
}
