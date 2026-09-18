package index

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_KeySplitIndex_Create(t *testing.T) {
	fi := KeySplitIndex[int]{}

	fi.Set("one", 1)

	requireEqualValues(t, &fi, m{
		"one": 1,
	})

	fi.Set("onesie", 101)

	requireEqualValues(t, &fi, m{
		"one": m{ // there is a value here
			"sie": 101,
		},
	})

	fi.Set("apple", 99)

	requireEqualValues(t, &fi, m{
		"one": m{
			"sie": 101,
		},
		"apple": 99,
	})

	fi.Set("alice", 999)

	requireEqualValues(t, &fi, m{
		"one": m{
			"sie": 101,
		},
		"a": m{
			"pple": 99,
			"lice": 999,
		},
	})
}

type m = map[string]any

func requireEqualValues[T comparable](t *testing.T, value *KeySplitIndex[T], expected m) {
	_requireNodeValues(t, &value.Node, "", expected)
}

func _requireNodeValues[T comparable](t *testing.T, value *Node[T], path string, expected any) {
	switch expected := expected.(type) {
	case T:
		if value.value != expected {
			t.Fatalf("values not equal: %v != %v", value.value, value)
		}
	case m:
		if len(value.keyMap) != len(expected) {
			t.Fatalf("number of children not equal: %v != %v", len(value.keyMap), len(expected))
		}
		for k, v := range expected {
			v2, ok := value.keyMap[k]
			if !ok {
				t.Fatalf("missing key: %s", k)
			} else {
				_requireNodeValues(t, v2, path, v)
			}
		}
	default:
		panic(fmt.Errorf("invalid type: %#v", expected))
	}
}

func Test_KeySplitIndex_Get(t *testing.T) {
	fi := KeySplitIndex[int]{}

	const (
		one    = 1
		two    = 2
		once   = 11
		onesie = 11
	)

	fi.Set("one", one)
	require.Equal(t, one, fi.Get("one"))

	fi.Set("two", two)
	require.Equal(t, one, fi.Get("one"))
	require.Equal(t, two, fi.Get("two"))

	fi.Set("once", once)
	require.Equal(t, one, fi.Get("one"))
	require.Equal(t, two, fi.Get("two"))
	require.Equal(t, once, fi.Get("once"))

	fi.Set("onesie", onesie)
	require.Equal(t, one, fi.Get("one"))
	require.Equal(t, two, fi.Get("two"))
	require.Equal(t, once, fi.Get("once"))
	require.Equal(t, onesie, fi.Get("onesie"))

	fi.Set("apple", 1000)
	require.Equal(t, one, fi.Get("one"))
	require.Equal(t, two, fi.Get("two"))
	require.Equal(t, once, fi.Get("once"))
	require.Equal(t, onesie, fi.Get("onesie"))

	fi.Set("alice", 1001)
	require.Equal(t, one, fi.Get("one"))
	require.Equal(t, two, fi.Get("two"))
	require.Equal(t, once, fi.Get("once"))
	require.Equal(t, onesie, fi.Get("onesie"))

	requireHasAll(t, []int{one, once, onesie}, fi.ByPrefix("o")...)
	requireHasAll(t, []int{one, once, onesie}, fi.ByPrefix("on")...)
	requireHasAll(t, []int{one, onesie}, fi.ByPrefix("one")...)
	requireHasAll(t, []int{onesie}, fi.ByPrefix("ones")...)
	requireHasAll(t, []int{onesie}, fi.ByPrefix("onesi")...)
	requireHasAll(t, []int{onesie}, fi.ByPrefix("onesie")...)
	requireHasAll(t, nil, fi.ByPrefix("onesies")...)
	requireHasAll(t, []int{two}, fi.ByPrefix("t")...)
	requireHasAll(t, []int{two}, fi.ByPrefix("tw")...)
	requireHasAll(t, []int{two}, fi.ByPrefix("two")...)
	requireHasAll(t, []int{}, fi.ByPrefix("twos")...)

	require.Equal(t, 0, fi.Get("invalid")) // returns the zero value
}

func Test_KeySplitIndex_serialization(t *testing.T) {
	index1 := KeySplitIndex[int]{}

	const (
		one    = 1
		two    = 2
		once   = 11
		onesie = 111
	)

	index1.Set("one", one)
	index1.Set("two", two)
	index1.Set("once", once)
	index1.Set("onesie", onesie)

	serialized, err := json.Marshal(&index1)
	require.NoError(t, err)

	require.JSONEq(t, `{"one":1,"two":2,"once":11,"onesie":111}`, string(serialized))

	var index2 KeySplitIndex[int]
	err = json.Unmarshal(serialized, &index2)
	require.NoError(t, err)

	require.Equal(t, &index1, &index2)
}

// requireHasAll asserts the values are exactly the required ones, in any order. Carried over with the
// index's own tests so they run here unchanged.
func requireHasAll[T comparable](t *testing.T, values []T, required ...T) {
	t.Helper()
	require.Len(t, values, len(required))
nextFound:
	for _, ex := range required {
		for _, existing := range values {
			if existing == ex {
				continue nextFound
			}
		}
		require.Fail(t, fmt.Sprintf("value %v isn't in slice %v", ex, values))
	}
}
