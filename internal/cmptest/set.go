package cmptest

type slicer[T any] interface {
	ToSlice() []T
}

func buildSetComparer[T any, S slicer[T]](l func(x, y T) bool) func(x, y S) bool {
	return func(x, y S) bool {
		xs := x.ToSlice()
		ys := y.ToSlice()

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
