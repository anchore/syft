package internal

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Map(t *testing.T) {
	type t1 string
	type t2 string
	tests := []struct {
		name     string
		in       []t1
		fn       func(t1) t2
		expected []t2
	}{
		{
			name: "basic",
			in:   []t1{"1", "2", "3"},
			fn: func(t t1) t2 {
				return t2(t)
			},
			expected: []t2{"1", "2", "3"},
		},
		{
			name: "replacing",
			in:   []t1{"1", "2", "3"},
			fn: func(t t1) t2 {
				return t2("new" + t)
			},
			expected: []t2{"new1", "new2", "new3"},
		},
	}
	for _, test := range tests {
		got := Map(test.in, test.fn)
		require.Equal(t, test.expected, got)
	}
}

func Test_Remove(t *testing.T) {
	tests := []struct {
		name     string
		in       []int
		fn       func(int) bool
		expected []int
	}{
		{
			name: "basic1",
			in:   []int{1, 2, 3, 4, 5},
			fn: func(i int) bool {
				return i < 3
			},
			expected: []int{3, 4, 5},
		},
		{
			name: "basic2",
			in:   []int{1, 2, 3, 4, 5},
			fn: func(i int) bool {
				return i > 3
			},
			expected: []int{1, 2, 3},
		},
	}
	for _, test := range tests {
		got := Remove(test.in, test.fn)
		require.Equal(t, test.expected, got)
	}
}
