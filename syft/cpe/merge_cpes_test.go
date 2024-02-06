package cpe

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Merge(t *testing.T) {
	tests := []struct {
		name     string
		input    [][]CPE
		expected []CPE
	}{
		{
			name: "merge, removing duplicates and ordered",
			input: [][]CPE{
				{
					Must("cpe:2.3:a:*:package:1:*:*:*:*:*:*:*", NVDDictionaryLookupSource),
					Must("cpe:2.3:a:*:package:1:*:*:*:*:*:*:*", DeclaredSource),
					Must("cpe:2.3:a:some:package:*:*:*:*:*:*:*:*", GeneratedSource),
				},
				{
					Must("cpe:2.3:a:some:package:1:*:*:*:*:*:*:*", DeclaredSource),
					Must("cpe:2.3:a:some:package:*:*:*:*:*:*:*:*", GeneratedSource),
				},
			},
			expected: []CPE{
				Must("cpe:2.3:a:*:package:1:*:*:*:*:*:*:*", NVDDictionaryLookupSource),
				Must("cpe:2.3:a:some:package:1:*:*:*:*:*:*:*", DeclaredSource),
				Must("cpe:2.3:a:*:package:1:*:*:*:*:*:*:*", DeclaredSource),
				Must("cpe:2.3:a:some:package:*:*:*:*:*:*:*:*", GeneratedSource),
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
