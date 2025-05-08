package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_SanitizeElementID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "letters",
			expected: "letters",
		},
		{
			input:    "ssl-client",
			expected: "ssl-client",
		},
		{
			input:    "ssl_client",
			expected: "ssl-client",
		},
		{
			input:    "go-module-sigs.k8s.io/structured-merge-diff/v3",
			expected: "go-module-sigs.k8s.io-structured-merge-diff-v3",
		},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			actual := SanitizeElementID(test.input)

			assert.Equal(t, test.expected, actual)
		})
	}
}
