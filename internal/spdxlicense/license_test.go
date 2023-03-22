package spdxlicense

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIDParse(t *testing.T) {
	var tests = []struct {
		shortName string
		id        string
		other     string
		found     bool
	}{
		{
			"GPL1only",
			"GPL-1.0-only",
			"",
			true,
		},
		{
			"GPL2",
			"GPL-2.0-only",
			"",
			true,
		},
		{
			"GPL2+",
			"GPL-2.0-or-later",
			"",
			true,
		},
		{
			"GPL3.0.0orlater",
			"GPL-3.0-or-later",
			"",
			true,
		},
		{
			"GPL3withautoconfexception",
			"GPL-3.0-with-autoconf-exception",
			"",
			true,
		},
		{
			"CCbync3de",
			"CC-BY-NC-3.0-DE",
			"",
			true,
		},
		// the below few cases are NOT expected, however, seem unavoidable given the current approach
		{
			"w3c20150513.0.0",
			"W3C-20150513",
			"",
			true,
		},
		{
			"spencer86.0.0",
			"Spencer-86",
			"",
			true,
		},
		{
			"unicodedfs2015.0.0",
			"Unicode-DFS-2015",
			"",
			true,
		},
		{
			"Unknown",
			"",
			"Unknown",
			true,
		},
		{
			"   ",
			"",
			"",
			false,
		},
	}

	for _, test := range tests {
		t.Run(test.shortName, func(t *testing.T) {
			value, other, exists := ID(test.shortName)
			assert.Equal(t, test.found, exists)
			assert.Equal(t, test.id, value)
			assert.Equal(t, test.other, other)
		})
	}
}
