package sort

import (
	"cmp"
	"fmt"
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
type TryComparableWrap[T Comparable[T]] struct {
	Data T
}

func (t TryComparableWrap[T]) TryCompare(other any) (bool, int) {
	if other == nil {
		return false, 0
	}

	switch other := other.(type) {
	case TryComparableWrap[T]:
		return true, t.Data.Compare(other.Data)
	case T:
		return true, t.Data.Compare(other)
	case *T:
		return true, ComparePtr(&t.Data, other)
	default:
		return false, 0
	}
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

type ComparableBool bool

func (b ComparableBool) Compare(other ComparableBool) int {
	if b == other {
		return 0
	}
	if b {
		return 1
	}
	return -1
}

type ComparableOrdMap[T cmp.Ordered, V cmp.Ordered] map[T]V

func (c ComparableOrdMap[K, V]) Compare(other ComparableOrdMap[K, V]) int {
	return CompareMapOrd(c, other)
}

type TryComparableMap[T cmp.Ordered, V TryComparable] map[T]V

func (c TryComparableMap[K, V]) TryCompare(other any) (bool, int) {
	switch other := other.(type) {
	case map[K]V:
		return tryCompareMap(c, other, func(v V) V { return v })
	case TryComparableMap[K, V]:
		return tryCompareMap(c, other, func(v V) V { return v })
	default:
		return false, 0
	}
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
	return Compare(ComparableBool(t1), ComparableBool(t2))
}

func tryCompareMap[K cmp.Ordered, V any, W TryComparable](t1 map[K]V, t2 map[K]V, wrap func(V) W) (bool, int) {
	// compare all common keys
	// if a key is found in t1, but not in t2 then t1 > t2
	for k, v1 := range t1 {
		if v2, exists := t2[k]; exists {
			if ok, i := TryCompare(wrap(v1), wrap(v2)); ok {
				if i != 0 {
					return true, i
				}
			} else {
				return false, 0
			}
		} else {
			return true, 1
		}
	}

	// if a key is found in t2, but not in t1 then t1 < t2
	// there is no need to check contents, because all commonm values have been checked before already
	for k := range t2 {
		if _, exists := t1[k]; !exists {
			return true, -1
		}
	}
	return true, 0
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
func TryCompare(a1 any, a2 any) (bool, int) {
	if a1 == nil && a2 == nil {
		return true, 0
	}
	if a1 == nil {
		return true, -1
	}
	if a2 == nil {
		return true, 1
	}
	if a1, ok := a1.(TryComparable); ok {
		return a1.TryCompare(a2)
	}
	return false, 0
}

func UnmarshalToTryComparable(t any) (TryComparable, error) {
	switch meta := t.(type) {
	case nil:
		t = nil
		return nil, nil
	case bool:
		return TryComparableWrap[ComparableBool]{Data: ComparableBool(meta)}, nil
	case float64:
		return TryComparableWrap[ComparableOrdered[float64]]{Data: ComparableOrdered[float64]{Data: meta}}, nil
	case float32:
		return TryComparableWrap[ComparableOrdered[float32]]{Data: ComparableOrdered[float32]{Data: meta}}, nil
	case int:
		return TryComparableWrap[ComparableOrdered[int]]{Data: ComparableOrdered[int]{Data: meta}}, nil
	case int8:
		return TryComparableWrap[ComparableOrdered[int8]]{Data: ComparableOrdered[int8]{Data: meta}}, nil
	case int16:
		return TryComparableWrap[ComparableOrdered[int16]]{Data: ComparableOrdered[int16]{Data: meta}}, nil
	case int32:
		return TryComparableWrap[ComparableOrdered[int32]]{Data: ComparableOrdered[int32]{Data: meta}}, nil
	case int64:
		return TryComparableWrap[ComparableOrdered[int64]]{Data: ComparableOrdered[int64]{Data: meta}}, nil
	case uint:
		return TryComparableWrap[ComparableOrdered[uint]]{Data: ComparableOrdered[uint]{Data: meta}}, nil
	case uint8:
		return TryComparableWrap[ComparableOrdered[uint8]]{Data: ComparableOrdered[uint8]{Data: meta}}, nil
	case uint16:
		return TryComparableWrap[ComparableOrdered[uint16]]{Data: ComparableOrdered[uint16]{Data: meta}}, nil
	case uint32:
		return TryComparableWrap[ComparableOrdered[uint32]]{Data: ComparableOrdered[uint32]{Data: meta}}, nil
	case uint64:
		return TryComparableWrap[ComparableOrdered[uint64]]{Data: ComparableOrdered[uint64]{Data: meta}}, nil
	case uintptr:
		return TryComparableWrap[ComparableOrdered[uintptr]]{Data: ComparableOrdered[uintptr]{Data: meta}}, nil
	case string:
		return TryComparableWrap[ComparableOrdered[string]]{Data: ComparableOrdered[string]{Data: meta}}, nil
	case map[string]any:
		var test = make(map[string]TryComparable)
		for k, v := range meta {
			v, err := UnmarshalToTryComparable(v)
			if err != nil {
				return nil, err
			}
			test[k] = v
		}
		return TryComparableMap[string, TryComparable](test), nil
	default:
		return nil, fmt.Errorf("unsupported format")
	}
}
