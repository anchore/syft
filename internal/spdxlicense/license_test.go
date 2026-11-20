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

func TestHasTopLevelOr(t *testing.T) {
	tests := []struct {
		expression string
		want       bool
	}{
		{"", false},
		{"MIT", false},
		{"MIT AND Apache-2.0", false},
		{"Apache-2.0 WITH LLVM-exception", false},
		{"MIT OR Apache-2.0", true},
		{"(MIT OR Apache-2.0)", false},
		{"ISC AND (BSD-3-Clause OR MIT)", false},
		{"MIT OR (Apache-2.0 AND BSD-3-Clause)", true},
		{"(GPL-2.0-only WITH Linux-syscall-note) OR MIT", true},
		{"(MIT OR Apache-2.0) OR (GPL-3.0-only AND LGPL-2.1-only)", true},
		{"(MIT AND (Apache-2.0 OR BSD-3-Clause))", false},
		{"LicenseRef-one-thing-first", false},
	}
	for _, tt := range tests {
		t.Run(tt.expression, func(t *testing.T) {
			assert.Equal(t, tt.want, HasTopLevelOr(tt.expression))
		})
	}
}
