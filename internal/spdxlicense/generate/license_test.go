package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	license1 = License{
		ID:         "ABC-1.0+",
		Name:       "The ABC License 1.0",
		Deprecated: true,
	}

	license2 = License{
		ID:   "ABC-1.0-or-later",
		Name: "The ABC License 1.0",
	}

	license3 = License{
		ID:         "ABC-1.0",
		Name:       "The ABC License 1.0 Only",
		Deprecated: true,
	}

	license4 = License{
		ID:   "ABC-1.0-only",
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

func TestLicense_canReplace(t *testing.T) {
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
		t.Run(tt.l1.ID+" - "+tt.l2.ID, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.l1.canReplace(tt.l2))
		})
	}
}

func TestLicensePermutations(t *testing.T) {
	var tests = []struct {
		shortName    string
		permutations []string
	}{
		{
			"GPL-1-only",
			[]string{
				"gpl1only",
				"gpl1.0only",
				"gpl1.0.0only",
			},
		},
		{
			"GPL-2",
			[]string{
				"gpl2",
				"gpl2.0",
				"gpl2.0.0",
			},
		},
		{
			"GPL-2.0+",
			[]string{
				"gpl2+",
				"gpl2.0+",
				"gpl2.0.0+",
			},
		},
		{
			"GPL-3.0.0-or-later",
			[]string{
				"gpl3orlater",
				"gpl3.0orlater",
				"gpl3.0.0orlater",
				"gpl3.0.0+",
				"gpl3.0+",
				"gpl3+",
			},
		},
		{
			"abc-1.1",
			[]string{
				"abc1",
				"abc1.1",
				"abc1.1.0",
			},
		},
		{
			"oldap-2.0",
			[]string{
				"oldap2",
				"oldap2.0",
				"oldap2.0.0",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.shortName, func(t *testing.T) {
			cleanID := cleanLicenseID(test.shortName)
			perms := buildLicenseIDPermutations(cleanID)
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

func Test_findReplacementLicense(t *testing.T) {
	tests := []struct {
		l        License
		expected *License
		licenses LicenseList
	}{
		{license1, nil, LicenseList{}},
		{license1, nil, LicenseList{Licenses: []License{license3}}},
		{license1, &license2, LicenseList{Licenses: []License{license2, license3}}},
		{license1, &license2, LicenseList{Licenses: []License{license2, license3, license4, license5}}},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, tt.licenses.findReplacementLicense(tt.l))
	}
}
