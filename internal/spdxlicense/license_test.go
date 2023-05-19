package spdxlicense

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSPDXIDRecognition(t *testing.T) {
	var tests = []struct {
		shortName string
		id        string
		found     bool
	}{
		{
			"GPL-1-only",
			"GPL-1.0-only",
			true,
		},
		{
			"gpl1",
			"GPL-1.0-only",
			true,
		},
		{
			"gpl-1",
			"GPL-1.0-only",
			true,
		},
		{
			"GPL-2",
			"GPL-2.0-only",
			true,
		},
		{
			"GPL-2+",
			"GPL-2.0-or-later",
			true,
		},
		{
			"GPL-3.0.0-or-later",
			"GPL-3.0-or-later",
			true,
		},
		{
			"GPL-3-with-autoconf-exception",
			"GPL-3.0-with-autoconf-exception",
			true,
		},
		{
			"CC-by-nc-3-de",
			"CC-BY-NC-3.0-DE",
			true,
		},
		// the below few cases are NOT expected, however, seem unavoidable given the current approach
		{
			"spencer-86.0.0",
			"Spencer-86",
			true,
		},
		{
			"unicode-dfs-2015.0.0",
			"Unicode-DFS-2015",
			true,
		},
		{
			"Unknown",
			"",
			false,
		},
		{
			"   ",
			"",
			false,
		},
	}

	for _, test := range tests {
		t.Run(test.shortName, func(t *testing.T) {
			value, exists := ID(test.shortName)
			assert.Equal(t, test.found, exists)
			assert.Equal(t, test.id, value)
		})
	}
}
