package cmptest

type slicer[T any] interface {
	ToSlice(sorter ...func(a, b T) int) []T
}

func buildSetComparer[T any, S slicer[T]](l func(x, y T) bool, sorters ...func(a, b T) int) func(x, y S) bool {
	return func(x, y S) bool {
		xs := x.ToSlice(sorters...)
		ys := y.ToSlice(sorters...)

		if len(xs) != len(ys) {
			return false
		}
		for i, xe := range xs {
			ye := ys[i]
			if !l(xe, ye) {
				return false
			}
		}

		return true
	}
}
