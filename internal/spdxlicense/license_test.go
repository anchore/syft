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
			"GPL-1-only",
			"GPL-1.0-only",
		},
		{
			"GPL-2",
			"GPL-2.0",
		},
		{
			"GPL-2+",
			"GPL-2.0+",
		},
		{
			"GPL-3.0.0-or-later",
			"GPL-3.0-or-later",
		},
		{
			"GPL-3-with-autoconf-exception",
			"GPL-3.0-with-autoconf-exception",
		},
		{
			"CC-by-nc-3-de",
			"CC-BY-NC-3.0-DE",
		},
	}

	for _, test := range tests {
		t.Run(test.shortName, func(t *testing.T) {
			got, exists := ID(test.shortName)
			assert.True(t, exists)
			assert.Equal(t, test.spdx, got)
		})
	}
}
