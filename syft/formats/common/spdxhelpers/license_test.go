package spdxhelpers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
)

func Test_License(t *testing.T) {
	tests := []struct {
		name     string
		input    pkg.Package
		expected struct {
			concluded string
			declared  string
		}
	}{
		{
			name:  "no licenses",
			input: pkg.Package{},
			expected: struct{ concluded, declared string }{
				concluded: "NOASSERTION",
				declared:  "NOASSERTION",
			},
		},
		{
			name: "no SPDX licenses",
			input: pkg.Package{
				Licenses: []pkg.License{
					{
						Value: "made-up",
						Type:  license.Declared,
					},
				},
			},
			expected: struct{ concluded, declared string }{
				concluded: "NOASSERTION",
				declared:  "LicenseRef-made-up",
			},
		},
		{
			name: "with SPDX license",
			input: pkg.Package{
				Licenses: []pkg.License{
					{
						SPDXExpression: "MIT",
						Type:           license.Declared,
					},
				},
			},
			expected: struct {
				concluded string
				declared  string
			}{
				concluded: "NOASSERTION",
				declared:  "MIT",
			},
		},
		{
			name: "with SPDX license expression",
			input: pkg.Package{
				Licenses: []pkg.License{
					{
						SPDXExpression: "MIT",
						Type:           license.Declared,
					},
					{
						SPDXExpression: "GPL-3.0-only",
						Type:           license.Declared,
					},
				},
			},
			expected: struct {
				concluded string
				declared  string
			}{
				concluded: "NOASSERTION",
				declared:  "MIT AND GPL-3.0-only",
			},
		},
		{
			name: "includes valid LicenseRef-",
			input: pkg.Package{
				Licenses: []pkg.License{
					{
						Value: "one thing first",
						Type:  license.Declared,
					},
					{
						Value: "two things/#$^second",
						Type:  license.Declared,
					},
					{
						Value: "MIT",
						Type:  license.Declared,
					},
				},
			},
			expected: struct {
				concluded string
				declared  string
			}{
				concluded: "NOASSERTION",
				declared:  "LicenseRef-one-thing-first AND LicenseRef-two-things----second AND LicenseRef-MIT",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c, d := License(test.input)
			assert.Equal(t, test.expected.concluded, c)
			assert.Equal(t, test.expected.declared, d)
		})
	}
}
