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
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicense("RandomLicense"),
				),
			},
			expected: &cyclonedx.Licenses{
				{
					License: &cyclonedx.License{
						Name: "RandomLicense",
					},
				},
			},
		},
		{
			name: "single SPDX ID and Non SPDX ID",
			input: pkg.Package{
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicense("mit"),
					pkg.NewLicense("FOOBAR"),
				),
			},
			expected: &cyclonedx.Licenses{
				{
					License: &cyclonedx.License{
						Name: "FOOBAR",
					},
				},
				{
					License: &cyclonedx.License{
						ID: "MIT",
					},
				},
			},
		},
		{
			name: "with complex SPDX license expression",
			input: pkg.Package{
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicense("MIT AND GPL-3.0-only"),
				),
			},
			expected: &cyclonedx.Licenses{
				{
					Expression: "MIT AND GPL-3.0-only",
				},
			},
		},
		{
			name: "with multiple complex SPDX license expression",
			input: pkg.Package{
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicense("MIT AND GPL-3.0-only"),
					pkg.NewLicense("MIT AND GPL-3.0-only WITH Classpath-exception-2.0"),
				),
			},
			expected: &cyclonedx.Licenses{
				{
					Expression: "(MIT AND GPL-3.0-only) AND (MIT AND GPL-3.0-only WITH Classpath-exception-2.0)",
				},
			},
		},
		{
			name: "consistent sorting across SPDX and other licenses",
			input: pkg.Package{
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicense("Apache-2.0"),
					pkg.NewLicense("ISC"),
					pkg.NewLicense("Apache"),
					pkg.NewLicense("Permission"),
					pkg.NewLicense("Python"),
					pkg.NewLicense("PSF-2.0"),
					pkg.NewLicense("This"),
					pkg.NewLicense("GPL-2.0-only"),
					pkg.NewLicense("See"),
					pkg.NewLicense("LGPL-2.1-or-later"),
				),
			},
			expected: &cyclonedx.Licenses{
				{
					License: &cyclonedx.License{
						ID: "Apache-2.0",
					},
				},
			},
		},
		{
			name: "deduplication of SPDX licenses with shared SPDX ID",
			input: pkg.Package{
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicense("Apache-2.0"),
					pkg.NewLicense("Apache-2"),
					pkg.NewLicenseFromURL("Apache-2.0", "https://spdx.org/licenses/Apache-2.0.html"),
				),
			},
			expected: &cyclonedx.Licenses{
				{
					License: &cyclonedx.License{
						ID:  "Apache-2.0",
						URL: "https://spdx.org/licenses/Apache-2.0.html",
					},
				},
			},
		},
		{
			name: "deduplication of Other licenses with shared value",
			input: pkg.Package{
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicense("python"),
					pkg.NewLicenseFromURL("python", "https://www.python.org/psf/license/"),
				),
			},
			expected: &cyclonedx.Licenses{
				{
					License: &cyclonedx.License{
						Name: "python",
						URL:  "https://spdx.org/licenses/Apache-2.0.html",
					},
				},
			},
		},
		// TODO: do we drop the non SPDX ID license and do a single expression
		// OR do we keep the non SPDX ID license and do multiple licenses where the complex
		// expressions are set as the NAME field?
		//{
		//	name: "with multiple complex SPDX license expression and a non spdx id",
		//	input: pkg.Package{
		//		Licenses: []pkg.License{
		//			{
		//				SPDXExpression: "MIT AND GPL-3.0-only",
		//			},
		//			{
		//				SPDXExpression: "MIT AND GPL-3.0-only WITH Classpath-exception-2.0",
		//			},
		//			{
		//				Value: "FOOBAR",
		//			},
		//		},
		//	},
		//	expected: &cyclonedx.Licenses{
		//		{
		//			Expression: "(MIT AND GPL-3.0-only) AND (MIT AND GPL-3.0-only WITH Classpath-exception-2.0)",
		//		},
		//	},
		//},
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
