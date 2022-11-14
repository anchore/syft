package cyclonedxhelpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_formatCPE(t *testing.T) {
	tests := []struct {
		cpe      string
		expected string
	}{
		{
			cpe:      "cpe:2.3:o:amazon:amazon_linux:2",
			expected: "cpe:2.3:o:amazon:amazon_linux:2:*:*:*:*:*:*:*",
		},
		{
			cpe:      "cpe:/o:opensuse:leap:15.2",
			expected: "cpe:2.3:o:opensuse:leap:15.2:*:*:*:*:*:*:*",
		},
		{
			cpe:      "invalid-cpe",
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.cpe, func(t *testing.T) {
			out := formatCPE(test.cpe)
			assert.Equal(t, test.expected, out)
		})
	}
}
