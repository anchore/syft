package cyclonedxhelpers

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
)

func Test_encodeLicense(t *testing.T) {
	tests := []struct {
		name     string
		input    pkg.Package
		expected *cyclonedx.Licenses
	}{
		{
			name:     "no licenses",
			input:    pkg.Package{},
			expected: nil,
		},
		{
			name: "no SPDX licenses",
			input: pkg.Package{
				Licenses: []string{
					"made-up",
				},
			},
			expected: nil,
		},
		{
			name: "with SPDX license",
			input: pkg.Package{
				Licenses: []string{
					"MIT",
				},
			},
			expected: &cyclonedx.Licenses{
				{License: &cyclonedx.License{ID: "MIT"}},
			},
		},
		{
			name: "with SPDX license expression",
			input: pkg.Package{
				Licenses: []string{
					"MIT",
					"GPL-3.0",
				},
			},
			expected: &cyclonedx.Licenses{
				{License: &cyclonedx.License{ID: "MIT"}},
				{License: &cyclonedx.License{ID: "GPL-3.0"}},
			},
		},
		{
			name: "cap insensitive",
			input: pkg.Package{
				Licenses: []string{
					"gpl-3.0",
				},
			},
			expected: &cyclonedx.Licenses{
				{License: &cyclonedx.License{ID: "GPL-3.0"}},
			},
		},
		{
			name: "debian to spdx conversion",
			input: pkg.Package{
				Licenses: []string{
					"GPL-2",
				},
			},
			expected: &cyclonedx.Licenses{
				{License: &cyclonedx.License{ID: "GPL-2.0"}},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, encodeLicenses(test.input))
		})
	}
}
