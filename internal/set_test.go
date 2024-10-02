package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSet(t *testing.T) {
	tests := []struct {
		name   string
		start  []int
		result Set[int]
	}{
		{"empty set", []int{}, NewSet[int]()},
		{"non-empty set", []int{1, 2, 3}, NewSet(1, 2, 3)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSet(tt.start...)
			require.Equal(t, tt.result, s)
		})
	}
}

func TestAdd(t *testing.T) {
	tests := []struct {
		name   string
		input  []int
		add    []int
		result Set[int]
	}{
		{"add to empty set", []int{}, []int{1, 2, 3}, NewSet(1, 2, 3)},
		{"add to non-empty set", []int{1}, []int{2, 3}, NewSet(1, 2, 3)},
		{"add existing elements", []int{1, 2}, []int{2, 3}, NewSet(1, 2, 3)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSet(tt.input...)
			s.Add(tt.add...)
			assert.Equal(t, tt.result, s)
		})
	}
}

func TestRemove(t *testing.T) {
	tests := []struct {
		name   string
		input  []int
		remove int
		result Set[int]
	}{
		{"remove from non-empty set", []int{1, 2, 3}, 2, NewSet(1, 3)},
		{"remove non-existent element", []int{1, 2}, 3, NewSet(1, 2)},
		{"remove from single-element set", []int{1}, 1, NewSet[int]()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSet(tt.input...)
			s.Remove(tt.remove)
			assert.Equal(t, tt.result, s)
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		name     string
		input    []int
		contains int
		result   bool
	}{
		{"element in set", []int{1, 2, 3}, 2, true},
		{"element not in set", []int{1, 2}, 3, false},
		{"empty set", []int{}, 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSet(tt.input...)
			assert.Equal(t, tt.result, s.Contains(tt.contains))
		})
	}
}

func TestToSlice(t *testing.T) {
	tests := []struct {
		name   string
		input  []int
		result []int
	}{
		{"non-empty set", []int{3, 1, 2}, []int{1, 2, 3}},
		{"empty set", []int{}, []int{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSet(tt.input...)
			assert.Equal(t, tt.result, s.ToSlice())
		})
	}
}

func TestEquals(t *testing.T) {
	tests := []struct {
		name   string
		set1   []int
		set2   []int
		result bool
	}{
		{"equal sets", []int{1, 2, 3}, []int{3, 2, 1}, true},
		{"different sets", []int{1, 2}, []int{2, 3}, false},
		{"empty sets", []int{}, []int{}, true},
		{"one empty set", []int{1, 2}, []int{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s1 := NewSet(tt.set1...)
			s2 := NewSet(tt.set2...)
			assert.Equal(t, tt.result, s1.Equals(s2))
		})
	}
}

func TestEmpty(t *testing.T) {
	tests := []struct {
		name   string
		input  []int
		result bool
	}{
		{"non-empty set", []int{1}, false},
		{"empty set", []int{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSet(tt.input...)
			assert.Equal(t, tt.result, s.Empty())
		})
	}
}
