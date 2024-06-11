package cache

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_hashType(t *testing.T) {
	type t1 struct {
		Name string
	}
	type t2 struct {
		Name string
	}
	type generic[T any] struct {
		Val T
	}
	tests := []struct {
		name     string
		hash     func() string
		expected string
	}{
		{
			name:     "struct 1",
			hash:     func() string { return hashType[t1]() },
			expected: "d106c3ffbf98a0b1",
		},
		{
			name:     "slice of struct 1",
			hash:     func() string { return hashType[[]t1]() },
			expected: "8122ace4ee1af0b4",
		},
		{
			name:     "slice of struct 2",
			hash:     func() string { return hashType[[]t2]() },
			expected: "8cc04b5808be5bf9",
		},
		{
			name:     "ptr 1",
			hash:     func() string { return hashType[*t1]() },
			expected: "d106c3ffbf98a0b1", // same hash as t1, which is ok since the structs are the same
		},
		{
			name:     "slice of ptr 1",
			hash:     func() string { return hashType[[]*t1]() },
			expected: "8122ace4ee1af0b4", // same hash as []t1, again underlying serialization is the same
		},
		{
			name:     "slice of ptr 2",
			hash:     func() string { return hashType[[]*t2]() },
			expected: "8cc04b5808be5bf9", // same hash as []t2, underlying serialization is the same
		},
		{
			name:     "slice of ptr of slice of ptr",
			hash:     func() string { return hashType[[]*[]*t1]() },
			expected: "500d9f5b3a5977ce",
		},
		{
			name:     "generic 1",
			hash:     func() string { return hashType[generic[t1]]() },
			expected: "b5fbb30e24400e81",
		},
		{
			name:     "generic 2",
			hash:     func() string { return hashType[generic[t2]]() },
			expected: "becdb767c6b22bfa",
		},
		{
			name:     "generic with ptr 1",
			hash:     func() string { return hashType[generic[*t1]]() },
			expected: "30c8855bf290fd83",
		},
		{
			name:     "generic with ptr 2",
			hash:     func() string { return hashType[generic[*t2]]() },
			expected: "b66366b6ce9e6361",
		},
		{
			name:     "generic with slice 1",
			hash:     func() string { return hashType[generic[[]t1]]() },
			expected: "d2ed158942fa6c29",
		},
		{
			name:     "generic with slice 2",
			hash:     func() string { return hashType[generic[[]t2]]() },
			expected: "7a7bec575871c179",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, test.hash())
		})
	}
}
