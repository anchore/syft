package cyclonedxhelpers

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg"
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
				Licenses: internal.LogicalStrings{
					Simple: []string{
						"made-up",
					},
				},
			},
			expected: &cyclonedx.Licenses{
				{License: &cyclonedx.License{Name: "made-up"}},
			},
		},
		{
			name: "with SPDX license",
			input: pkg.Package{
				Licenses: internal.LogicalStrings{
					Simple: []string{
						"MIT",
					},
				},
			},
			expected: &cyclonedx.Licenses{
				{License: &cyclonedx.License{ID: "MIT"}},
			},
		},
		{
			name: "with SPDX license expression",
			input: pkg.Package{
				Licenses: internal.LogicalStrings{
					Simple: []string{
						"MIT",
						"GPL-3.0",
					},
				},
			},
			expected: &cyclonedx.Licenses{
				{License: &cyclonedx.License{ID: "MIT"}},
				{License: &cyclonedx.License{ID: "GPL-3.0-only"}},
			},
		},
		{
			name: "cap insensitive",
			input: pkg.Package{
				Licenses: internal.LogicalStrings{
					Simple: []string{
						"gpl-3.0",
					},
				},
			},
			expected: &cyclonedx.Licenses{
				{License: &cyclonedx.License{ID: "GPL-3.0-only"}},
			},
		},
		{
			name: "debian to spdx conversion",
			input: pkg.Package{
				Licenses: internal.LogicalStrings{
					Simple: []string{
						"GPL-2",
					},
				},
			},
			expected: &cyclonedx.Licenses{
				{License: &cyclonedx.License{ID: "GPL-2.0-only"}},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, encodeLicenses(test.input))
		})
	}
}
