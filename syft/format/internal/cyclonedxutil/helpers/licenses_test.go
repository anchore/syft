package helpers

import (
	"context"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
)

func Test_encodeLicense(t *testing.T) {
	ctx := context.TODO()
	tests := []struct {
		name     string
		input    pkg.Package
		expected *cyclonedx.Licenses
	}{
		{
			name:  "no licenses",
			input: pkg.Package{},
		},
		{
			name: "no SPDX licenses",
			input: pkg.Package{
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseWithContext(ctx, "RandomLicense"),
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
					pkg.NewLicenseWithContext(ctx, "mit"),
					pkg.NewLicenseWithContext(ctx, "FOOBAR"),
				),
			},
			expected: &cyclonedx.Licenses{
				{
					License: &cyclonedx.License{
						ID: "MIT",
					},
				},
				{
					License: &cyclonedx.License{
						Name: "FOOBAR",
					},
				},
			},
		},
		{
			name: "with complex SPDX license expression",
			input: pkg.Package{
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseWithContext(ctx, "MIT AND GPL-3.0-only"),
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
					pkg.NewLicenseWithContext(ctx, "MIT AND GPL-3.0-only"),
					pkg.NewLicenseWithContext(ctx, "MIT AND GPL-3.0-only WITH Classpath-exception-2.0"),
				),
			},
			expected: &cyclonedx.Licenses{
				{
					Expression: "(MIT AND GPL-3.0-only) AND (MIT AND GPL-3.0-only WITH Classpath-exception-2.0)",
				},
			},
		},
		{
			name: "with multiple URLs and expressions",
			input: pkg.Package{
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromURLsWithContext(ctx, "MIT", "https://opensource.org/licenses/MIT", "https://spdx.org/licenses/MIT.html"),
					pkg.NewLicenseWithContext(ctx, "MIT AND GPL-3.0-only"),
					pkg.NewLicenseFromURLsWithContext(ctx, "FakeLicense", "htts://someurl.com"),
				),
			},
			expected: &cyclonedx.Licenses{
				{
					License: &cyclonedx.License{
						ID:  "MIT",
						URL: "https://opensource.org/licenses/MIT",
					},
				},
				{
					License: &cyclonedx.License{
						ID:  "MIT",
						URL: "https://spdx.org/licenses/MIT.html",
					},
				},
				{
					License: &cyclonedx.License{
						Name: "FakeLicense",
						URL:  "htts://someurl.com",
					},
				},
				{
					License: &cyclonedx.License{
						Name: "MIT AND GPL-3.0-only",
					},
				},
			},
		},
		{
			name: "with URL only and no name or SPDX ID",
			input: pkg.Package{
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromURLsWithContext(ctx, "", "http://jaxen.codehaus.org/license.html"),
				),
			},
			expected: &cyclonedx.Licenses{
				{
					License: &cyclonedx.License{
						Name: "http://jaxen.codehaus.org/license.html",
						URL:  "http://jaxen.codehaus.org/license.html",
					},
				},
			},
		},
		{
			name: "with multiple values licenses are deduplicated",
			input: pkg.Package{
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseWithContext(ctx, "Apache-2"),
					pkg.NewLicenseWithContext(ctx, "Apache-2.0"),
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
			name: "with multiple URLs and single with no URLs",
			input: pkg.Package{
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseWithContext(ctx, "MIT"),
					pkg.NewLicenseFromURLsWithContext(ctx, "MIT", "https://opensource.org/licenses/MIT", "https://spdx.org/licenses/MIT.html"),
					pkg.NewLicenseWithContext(ctx, "MIT AND GPL-3.0-only"),
				),
			},
			expected: &cyclonedx.Licenses{
				{
					License: &cyclonedx.License{
						ID:  "MIT",
						URL: "https://opensource.org/licenses/MIT",
					},
				},
				{
					License: &cyclonedx.License{
						ID:  "MIT",
						URL: "https://spdx.org/licenses/MIT.html",
					},
				},
				{
					License: &cyclonedx.License{
						Name: "MIT AND GPL-3.0-only",
					},
				},
			},
		},
		{
			name: "single parenthesized SPDX expression",
			input: pkg.Package{
				Licenses: pkg.NewLicenseSet(pkg.NewLicensesFromValuesWithContext(ctx, "(MIT OR Apache-2.0)")...),
			},
			expected: &cyclonedx.Licenses{
				{
					Expression: "MIT OR Apache-2.0",
				},
			},
		},
		{
			name: "single license AND to parenthesized SPDX expression",
			// (LGPL-3.0-or-later OR GPL-2.0-or-later OR (LGPL-3.0-or-later AND GPL-2.0-or-later)) AND GFDL-1.3-invariants-or-later
			input: pkg.Package{
				Licenses: pkg.NewLicenseSet(pkg.NewLicensesFromValuesWithContext(ctx, "(LGPL-3.0-or-later OR GPL-2.0-or-later OR (LGPL-3.0-or-later AND GPL-2.0-or-later)) AND GFDL-1.3-invariants-or-later")...),
			},
			expected: &cyclonedx.Licenses{
				{
					Expression: "(LGPL-3.0-or-later OR GPL-2.0-or-later OR (LGPL-3.0-or-later AND GPL-2.0-or-later)) AND GFDL-1.3-invariants-or-later",
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
			if d := cmp.Diff(test.expected, encodeLicenses(test.input)); d != "" {
				t.Errorf("unexpected license (-want +got):\n%s", d)
			}
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
						// CycloneDX specification doesn't allow to provide License if Expression is provided
						License:    nil,
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
