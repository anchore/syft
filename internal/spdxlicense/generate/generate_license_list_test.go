package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			"abc-1.1",
			[]string{
				"abc-1",
				"abc-1.1",
				"abc-1.1.0",
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

var (
	license1 = License{
		ID:         "ABC-1.0+",
		Name:       "The ABC License 1.0",
		Deprecated: true,
	}

	license2 = License{
		ID:   "ABC-1.0-Or-later",
		Name: "The ABC License 1.0",
	}

	license3 = License{
		ID:         "ABC-1.0",
		Name:       "The ABC License 1.0 Only",
		Deprecated: true,
	}

	license4 = License{
		ID:   "ABC-1.0-Only",
		Name: "The ABC License 1.0 Only",
	}
	license5 = License{
		ID:         "Duh-1.0",
		Name:       "The Duh License 1.0",
		Deprecated: true,
	}
	license6 = License{
		ID:         "Duh-1.0-duh",
		Name:       "The Duh License 1.0",
		Deprecated: true,
	}
)

func Test_canReplace(t *testing.T) {
	tests := []struct {
		l1, l2   License
		expected bool
	}{
		{license1, license2, false},
		{license2, license1, true},
		{license2, license3, false},
		{license3, license2, false},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, tt.l1.canReplace(tt.l2))
	}
}

func Test_findEquivalentLicense(t *testing.T) {
	tests := []struct {
		l        License
		expected *License
		licenses []License
	}{
		{license1, nil, []License{}},
		{license1, nil, []License{license3}},
		{license1, &license2, []License{license2, license3}},
		{license1, &license2, []License{license2, license3, license4, license5}},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, findEquivalentLicense(tt.l, tt.licenses))
	}
}

func TestReplaceDeprecatedLicenses(t *testing.T) {
	results := LicenseList{
		Licenses: []License{
			license1,
			license2,
			license3,
			license4,
			license5,
			license6,
		},
	}

	expected := map[string]string{
		"abc-1":              "ABC-1.0-Only",
		"abc-1-only":         "ABC-1.0-Only",
		"abc-1.0":            "ABC-1.0-Only",
		"abc-1.0.0":          "ABC-1.0-Only",
		"abc-1.0-only":       "ABC-1.0-Only",
		"abc-1.0.0-only":     "ABC-1.0-Only",
		"abc-1+":             "ABC-1.0-Or-later",
		"abc-1.0+":           "ABC-1.0-Or-later",
		"abc-1.0.0+":         "ABC-1.0-Or-later",
		"abc-1-or-later":     "ABC-1.0-Or-later",
		"abc-1.0-or-later":   "ABC-1.0-Or-later",
		"abc-1.0.0-or-later": "ABC-1.0-Or-later",
		"duh-1":              "Duh-1.0",
		"duh-1.0":            "Duh-1.0",
		"duh-1.0.0":          "Duh-1.0",
		"duh-1-duh":          "Duh-1.0-duh",
		"duh-1.0-duh":        "Duh-1.0-duh",
		"duh-1.0.0-duh":      "Duh-1.0-duh",
	}

	licenses := processSPDXLicense(results)
	for k, v := range licenses {
		e := expected[k]
		require.Equal(t, e, v, k)
	}
}
