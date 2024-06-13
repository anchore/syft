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
	if cmp.Data < other.Data {
		return 1
	}
	if cmp.Data > other.Data {
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
func CompareBool(t1 bool, t2 bool) int {
	if t1 == t2 {
		return 0
	}
	if t1 {
		return 1
	}
	return -1
}
func compareMap[K cmp.Ordered, V any, W Comparable[W]](t1 map[K]V, t2 map[K]V, wrap func(V) W) int {
	// compare all common keys
	// if a key is found in t1, but not in t2 then t1 > t2
	for k, v1 := range t1 {
		if v2, exists := t2[k]; exists {
			if i := Compare(wrap(v1), wrap(v2)); i != 0 {
				return i
			}
		} else {
			return 1
		}
	}

	// if a key is found in t2, but not in t1 then t1 < t2
	// there is no need to check contents, because all commonm values have been checked before already
	for k := range t2 {
		if _, exists := t1[k]; !exists {
			return -1
		}
	}
	return 0
}
func CompareMap[K cmp.Ordered, V Comparable[V]](t1 map[K]V, t2 map[K]V) int {
	compFunc := func(v V) V {
		return v
	}
	return compareMap(t1, t2, compFunc)
}
func CompareMapOrd[K cmp.Ordered, V cmp.Ordered](t1 map[K]V, t2 map[K]V) int {
	compFunc := func(v V) ComparableOrdered[V] {
		return ComparableOrdered[V]{Data: v}
	}
	return compareMap(t1, t2, compFunc)
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
func TryCompare(a1 TryComparable, a2 any) (bool, int) {
	if a1 == nil && a2 == nil {
		return true, 0
	}
	if a1 == nil {
		return true, -1
	}
	if a2 == nil {
		return true, 1
	}
	return a1.TryCompare(a2)
}
