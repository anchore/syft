package cpe

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Merge(t *testing.T) {
	tests := []struct {
		name     string
		input    [][]Attributes
		expected []Attributes
	}{
		{
			name: "merge, removing duplicates and ordered",
			input: [][]Attributes{
				{
					Must("cpe:2.3:a:*:package:1:*:*:*:*:*:*:*"),
					Must("cpe:2.3:a:some:package:*:*:*:*:*:*:*:*"),
				},
				{
					Must("cpe:2.3:a:some:package:1:*:*:*:*:*:*:*"),
					Must("cpe:2.3:a:some:package:*:*:*:*:*:*:*:*"),
				},
			},
			expected: []Attributes{
				Must("cpe:2.3:a:some:package:1:*:*:*:*:*:*:*"),
				Must("cpe:2.3:a:some:package:*:*:*:*:*:*:*:*"),
				Must("cpe:2.3:a:*:package:1:*:*:*:*:*:*:*"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out := Merge(test.input[0], test.input[1])
			assert.Equal(t, test.expected, out)
		})
	}
}
