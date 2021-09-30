package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLicensePermutations(t *testing.T) {
	var tests = []struct {
		shortName    string
		permutations []string
	}{
		{
			"GPL-1-only",
			[]string{
				"GPL-1-only",
				"GPL-1.0-only",
				"GPL-1.0.0-only",
			},
		},
		{
			"GPL-2",
			[]string{
				"GPL-2",
				"GPL-2.0",
				"GPL-2.0.0",
			},
		},
		{
			"GPL-2.0+",
			[]string{
				"GPL-2+",
				"GPL-2.0+",
				"GPL-2.0.0+",
			},
		},
		{
			"GPL-3.0.0-or-later",
			[]string{
				"GPL-3-or-later",
				"GPL-3.0-or-later",
				"GPL-3.0.0-or-later",
			},
		},
		{
			"oldap-2.0",
			[]string{
				"oldap-2",
				"oldap-2.0",
				"oldap-2.0.0",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.shortName, func(t *testing.T) {
			perms := buildLicensePermutations(test.shortName)
			assert.ElementsMatch(t, test.permutations, perms)
		})
	}
}

func TestVersionPermutations(t *testing.T) {
	var tests = []struct {
		version      []string
		permutations []string
	}{
		{
			[]string{"1", "0"},
			[]string{"1", "1.0", "1.0.0"},
		},
		{
			[]string{"2"},
			[]string{"2", "2.0", "2.0.0"},
		},
		{
			[]string{"2", "0"},
			[]string{"2", "2.0", "2.0.0"},
		},

		{
			[]string{"3", "0", "0"},
			[]string{"3", "3.0", "3.0.0"},
		},
		{
			[]string{"0", "3"},
			[]string{"0.3", "0.3.0"},
		},
		{
			[]string{"0", "0", "3"},
			[]string{"0.0.3"},
		},
	}

	for _, test := range tests {
		t.Run(strings.Join(test.version, "."), func(t *testing.T) {
			got := versionPermutations(test.version)
			assert.ElementsMatch(t, test.permutations, got)
		})
	}
}

func TestFindLicenseVersion(t *testing.T) {
	var tests = []struct {
		license string
		version []string
	}{
		{
			"GPL-1.0-only",
			[]string{"1", "0"},
		},
		{
			"GPL-2.0",
			[]string{"2", "0"},
		},
		{
			"GPL-2.0.0",
			[]string{"2", "0", "0"},
		},
		{
			"GPL-2",
			[]string{"2"},
		},
		{
			"bzip2-1",
			[]string{"1"},
		},
		{
			"php-3.01",
			[]string{"3", "01"},
		},
		{
			"oldap-2.0",
			[]string{"2", "0"},
		},
	}

	for _, test := range tests {
		t.Run(test.license, func(t *testing.T) {
			got := findLicenseVersion(test.license)
			assert.Equal(t, test.version, got)
		})
	}
}
