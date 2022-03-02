package syft

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIdentify(t *testing.T) {
	tests := []struct {
		fixture  string
		expected string
	}{
		{
			fixture:  "test-fixtures/alpine-syft.json",
			expected: string(JSONFormatOption),
		},
	}
	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			f, err := os.Open(test.fixture)
			assert.NoError(t, err)
			by, err := io.ReadAll(f)
			assert.NoError(t, err)
			frmt := IdentifyFormat(by)
			assert.NotNil(t, frmt)
			assert.Equal(t, test.expected, frmt.Names()[0])
		})
	}
}
