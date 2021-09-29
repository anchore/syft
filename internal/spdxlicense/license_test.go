package spdxlicense

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIDParse(t *testing.T) {
	var tests = []struct {
		shortName string
		spdx      string
	}{
		{
			"gpl-1-only",
			"GPL-1.0-only",
		},
		{
			"gpl-2+",
			"GPL-2.0+",
		},
		{
			"gpl-3.0.0-or-later",
			"GPL-3.0-or-later",
		},
	}

	for _, test := range tests {
		got, exists := ID(test.shortName)
		if exists {
			assert.Equal(t, got, test.spdx)
			return
		}
		t.Fatalf("wanted: %s given: %s; failed to find", test.spdx, test.shortName)
	}
}
