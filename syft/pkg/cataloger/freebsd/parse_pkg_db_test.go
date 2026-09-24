package freebsd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_licenseLogicName(t *testing.T) {
	tests := []struct {
		name     string
		logic    int64
		expected string
	}{
		{name: "single", logic: 1, expected: "single"},
		{name: "or", logic: '|', expected: "or"},
		{name: "and", logic: '&', expected: "and"},
		{name: "unknown", logic: 99, expected: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, licenseLogicName(test.logic))
		})
	}
}
