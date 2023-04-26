package cyclonedxhelpers

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/license"
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
				Licenses: []pkg.License{},
			},
			expected: nil,
		},
		{
			name: "with SPDX license",
			input: pkg.Package{
				Licenses: []pkg.License{
					{
						Value:          "mit",
						SPDXExpression: "MIT",
					},
				},
			},
			expected: &cyclonedx.Licenses{
				{
					Expression: "MIT",
				},
			},
		},
		{
			name: "with SPDX license expression",
			input: pkg.Package{
				Licenses: []pkg.License{
					{
						Value:          "mit",
						SPDXExpression: "MIT",
					},
					{
						Value:          "gpl-3.0-only",
						SPDXExpression: "GPL-3.0-only",
					},
				},
			},
			expected: &cyclonedx.Licenses{
				{
					Expression: "MIT",
				},
				{
					Expression: "GPL-3.0-only",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, encodeLicenses(test.input))
		})
	}
}

func TestDecodeLicenses(t *testing.T) {
	tests := []struct {
		name     string
		input    *cyclonedx.Component
		expected []pkg.License
	}{
		{
			name:     "no licenses",
			input:    &cyclonedx.Component{},
			expected: []pkg.License{},
		},
		{
			name: "no SPDX license ID or expression",
			input: &cyclonedx.Component{
				Licenses: &cyclonedx.Licenses{
					{
						License: &cyclonedx.License{
							Name: "RandomLicense",
						},
					},
				},
			},
			expected: []pkg.License{
				{
					Value: "RandomLicense",
					// CycloneDX specification doesn't give a field for determining the license type
					Type: license.Declared,
				},
			},
		},
		{
			name: "with SPDX license ID",
			input: &cyclonedx.Component{
				Licenses: &cyclonedx.Licenses{
					{
						License: &cyclonedx.License{
							ID: "MIT",
						},
						Expression: "MIT",
					},
				},
			},
			expected: []pkg.License{
				{
					Value:          "MIT",
					SPDXExpression: "MIT",
					Type:           license.Declared,
				},
			},
		},
		{
			name: "with complex SPDX license expression",
			input: &cyclonedx.Component{
				Licenses: &cyclonedx.Licenses{
					{
						License:    &cyclonedx.License{},
						Expression: "MIT AND GPL-3.0-only WITH Classpath-exception-2.0",
					},
				},
			},
			expected: []pkg.License{
				{
					Value:          "MIT AND GPL-3.0-only WITH Classpath-exception-2.0",
					SPDXExpression: "MIT AND GPL-3.0-only WITH Classpath-exception-2.0",
					Type:           license.Declared,
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, decodeLicenses(test.input))
		})
	}
}
