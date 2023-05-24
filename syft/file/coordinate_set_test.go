package file

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
)

func TestCoordinatesSet(t *testing.T) {

	binA := Coordinates{
		RealPath:     "/bin",
		FileSystemID: "a",
	}

	binB := Coordinates{
		RealPath:     "/bin",
		FileSystemID: "b",
	}

	tests := []struct {
		name     string
		input    []Coordinates
		expected []Coordinates
	}{
		{
			name: "de-dup same location",
			input: []Coordinates{
				binA, binA, binA,
			},
			expected: []Coordinates{
				binA,
			},
		},
		{
			name: "dont de-dup different filesystem",
			input: []Coordinates{
				binB, binA,
			},
			expected: []Coordinates{
				binA, binB,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			set := NewCoordinateSet(test.input...)
			assert.Equal(t, test.expected, set.ToSlice())
		})
	}
}

func TestCoordinateSet_Hash(t *testing.T) {
	etcA := Coordinates{
		RealPath:     "/etc",
		FileSystemID: "a",
	}

	etcB := Coordinates{
		RealPath:     "/etc",
		FileSystemID: "b",
	}

	binA := Coordinates{
		RealPath:     "/bin",
		FileSystemID: "a",
	}

	binB := Coordinates{
		RealPath:     "/bin",
		FileSystemID: "b",
	}

	tests := []struct {
		name string
		setA CoordinateSet
		setB CoordinateSet
		want assert.ComparisonAssertionFunc
	}{
		{
			name: "empty sets have the same hash",
			setA: NewCoordinateSet(),
			setB: NewCoordinateSet(),
			want: assert.Equal,
		},
		{
			name: "sets with same elements have the same hash",
			setA: NewCoordinateSet(binA, etcA),
			setB: NewCoordinateSet(etcA, binA),
			want: assert.Equal,
		},
		{
			name: "sets with different elements have different hashes",
			setA: NewCoordinateSet(binA, etcA),
			setB: NewCoordinateSet(binA),
			want: assert.NotEqual,
		},
		{
			name: "sets with same paths but different FS IDs have different hashes",
			setA: NewCoordinateSet(etcA, binA),
			setB: NewCoordinateSet(etcB, binB),
			want: assert.NotEqual,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotA, err := artifact.IDByHash(tt.setA)
			require.NoError(t, err)
			gotB, err := artifact.IDByHash(tt.setB)
			require.NoError(t, err)
			tt.want(t, gotA, gotB)
		})
	}
}
