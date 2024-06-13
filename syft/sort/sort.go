package sort

import (
	"cmp"
	"slices"
)

type TryComparable interface {
	// TryCompare returns an integer comparing two T's.
	// If the two types are comparable, the canBeCompared will be true and result is meaningful.
	// The result will be 0 if a == b, negative if a < b, and positive if a > b.
	TryCompare(any) (canBeCompared bool, result int)
}
type Comparable[T any] interface {
	// Compare returns an integer comparing two T's.
	// The result will be 0 if a == b, negative if a < b, and positive if a > b.
	Compare(T) int
}

type ComparablePtr[T Comparable[T]] struct {
	Data *T
}

func Wrap[T cmp.Ordered](t *T) *ComparableOrdered[T] {
	if t == nil {
		return nil
	}
	return &ComparableOrdered[T]{Data: *t}
}

func (cmp ComparablePtr[T]) Compare(other ComparablePtr[T]) int {
	if cmp.Data != nil && other.Data != nil {
		return (*cmp.Data).Compare(*other.Data)
	}
	// nil == nil
	if cmp.Data == nil && other.Data == nil {
		return 0
	}
	// a Value > nil
	if cmp.Data != nil {
		return 1
	}
	// nil < a Value
	return -1
}

type ComparableOrdered[T cmp.Ordered] struct {
	Data T
}

func (cmp ComparableOrdered[T]) Compare(other ComparableOrdered[T]) int {
	if cmp.Data > other.Data {
		return 1
	}
	if cmp.Data < other.Data {
		return -1
	}
	return 0
}

func Less[T Comparable[T]](t1 T, t2 T) bool {
	return t1.Compare(t2) < 0
}

func Compare[T Comparable[T]](t1 T, t2 T) int {
	return t1.Compare(t2)
}
func CompareOrd[T cmp.Ordered](t1 T, t2 T) int {
	return ComparableOrdered[T]{Data: t1}.Compare(ComparableOrdered[T]{Data: t2})
}
func ComparePtrOrd[T cmp.Ordered](t1 *T, t2 *T) int {
	return ComparePtr(Wrap(t1), Wrap(t2))
}
func ComparePtr[T Comparable[T]](t1 *T, t2 *T) int {
	return ComparablePtr[T]{Data: t1}.Compare(ComparablePtr[T]{Data: t2})
}

func CompareArrays[T Comparable[T]](a1 []T, a2 []T) int {
	compareFunc := func(a T, b T) int {
		return a.Compare(b)
	}
	slices.SortStableFunc(a1, compareFunc)
	slices.SortStableFunc(a2, compareFunc)
	return slices.CompareFunc(a1, a2, compareFunc)
}
func CompareArraysOrd[T cmp.Ordered](a1 []T, a2 []T) int {
	slices.Sort(a1)
	slices.Sort(a2)
	return slices.Compare(a1, a2)
}
