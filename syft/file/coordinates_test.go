package file

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCoordinateSet(t *testing.T) {

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
			assert.Equal(t, test.expected, NewCoordinateSet(test.input...).ToSlice())
		})
	}
}
