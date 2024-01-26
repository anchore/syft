package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_noneIfEmpty(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{
			name:     "non-zero value",
			value:    "something",
			expected: "something",
		},
		{
			name:     "empty",
			value:    "",
			expected: NONE,
		},
		{
			name:     "space",
			value:    " ",
			expected: NONE,
		},
		{
			name:     "tab",
			value:    "\t",
			expected: NONE,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, NoneIfEmpty(test.value))
		})
	}
}
