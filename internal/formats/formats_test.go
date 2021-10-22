package formats

import (
	"io"
	"os"
	"testing"

	"github.com/anchore/syft/syft/format"
	"github.com/stretchr/testify/assert"
)

func TestIdentify(t *testing.T) {
	tests := []struct {
		fixture  string
		expected format.Option
	}{
		{
			fixture:  "test-fixtures/alpine-syft.json",
			expected: format.JSONOption,
		},
		{
			fixture:  "test-fixtures/alpine-spdx.json",
			expected: format.SPDXJSONOption,
		},
	}
	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			f, err := os.Open(test.fixture)
			assert.NoError(t, err)
			by, err := io.ReadAll(f)
			assert.NoError(t, err)
			frmt, err := Identify(by)
			assert.NoError(t, err)
			assert.NotNil(t, frmt)
			assert.Equal(t, test.expected, frmt.Option)
		})
	}
}
