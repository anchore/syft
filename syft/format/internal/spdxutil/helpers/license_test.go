package helpers

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/internal/spdxlicense"
	"github.com/anchore/syft/syft/pkg"
)

func Test_License(t *testing.T) {
	ctx := context.TODO()
	type expected struct {
		concluded string
		declared  string
	}
	tests := []struct {
		name     string
		input    pkg.Package
		expected expected
	}{
		{
			name:  "no licenses",
			input: pkg.Package{},
			expected: expected{
				concluded: "NOASSERTION",
				declared:  "NOASSERTION",
			},
		},
		{
			name: "no SPDX licenses",
			input: pkg.Package{
				Licenses: pkg.NewLicenseSet(pkg.NewLicenseWithContext(ctx, "made-up")),
			},
			expected: expected{
				concluded: "NOASSERTION",
				declared:  "LicenseRef-made-up",
			},
		},
		{
			name: "with SPDX license",
			input: pkg.Package{
				Licenses: pkg.NewLicenseSet(pkg.NewLicenseWithContext(ctx, "MIT")),
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
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseWithContext(ctx, "MIT"),
					pkg.NewLicenseWithContext(ctx, "GPL-3.0-only"),
				),
			},
			expected: expected{
				concluded: "NOASSERTION",
				// because we sort licenses alphabetically GPL ends up at the start
				declared: "GPL-3.0-only AND MIT",
			},
		},
		{
			name: "includes valid LicenseRef-",
			input: pkg.Package{
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseWithContext(ctx, "one thing first"),
					pkg.NewLicenseWithContext(ctx, "two things/#$^second"),
					pkg.NewLicenseWithContext(ctx, "MIT"),
				),
			},
			expected: expected{
				concluded: "NOASSERTION",
				// because we separate licenses between valid SPDX and non valid, valid ID always end at the front
				declared: "MIT AND LicenseRef-one-thing-first AND LicenseRef-two-things----second",
			},
		},
		{
			name: "join parentheses correctly",
			input: pkg.Package{
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseWithContext(ctx, "one thing first"),
					pkg.NewLicenseWithContext(ctx, "MIT AND GPL-3.0-only"),
					pkg.NewLicenseWithContext(ctx, "MIT OR APACHE-2.0"),
				),
			},
			expected: expected{
				concluded: "NOASSERTION",
				// because we separate licenses between valid SPDX and non valid, valid ID always end at the front
				declared: "(MIT AND GPL-3.0-only) AND (MIT OR APACHE-2.0) AND LicenseRef-one-thing-first",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c, d, _ := License(test.input)
			assert.Equal(t, test.expected.concluded, c)
			assert.Equal(t, test.expected.declared, d)
		})
	}
}

func TestGenerateLicenseID(t *testing.T) {
	tests := []struct {
		name     string
		license  pkg.License
		expected string
	}{
		{
			name: "SPDX expression is preferred",
			license: pkg.License{
				SPDXExpression: "Apache-2.0",
				Value:          "SomeValue",
				Contents:       "Some text",
			},
			expected: "Apache-2.0",
		},
		{
			name: "Uses value if no SPDX expression",
			license: pkg.License{
				Value: "my-sweet-custom-license",
			},
			expected: spdxlicense.LicenseRefPrefix + "my-sweet-custom-license",
		},
		{
			// note: this is an oversight of the SPDX spec. It does NOT allow "+" in the ID even though they are
			//  significant to the licenses in the expressions below
			name: "Long value is sanitized correctly",
			license: pkg.License{
				Value: "LGPLv2+ and LGPLv2+ with exceptions and GPLv2+ and GPLv2+ with exceptions and BSD and Inner-Net and ISC and Public Domain and GFDL",
			},
			expected: spdxlicense.LicenseRefPrefix +
				"LGPLv2--and-LGPLv2--with-exceptions-and-GPLv2--and-GPLv2--with-exceptions-and-BSD-and-Inner-Net-and-ISC-and-Public-Domain-and-GFDL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := generateLicenseID(tt.license)
			if tt.expected == "" {
				assert.True(t, len(id) > len(spdxlicense.LicenseRefPrefix))
				assert.Contains(t, id, spdxlicense.LicenseRefPrefix)
			} else {
				assert.Equal(t, tt.expected, id)
			}
		})
	}
}

func Test_joinLicenses(t *testing.T) {
	tests := []struct {
		name string
		args []SPDXLicense
		want string
	}{
		{
			name: "multiple licenses",
			args: []SPDXLicense{{ID: "MIT"}, {ID: "GPL-3.0-only"}},
			want: "MIT AND GPL-3.0-only",
		},
		{
			name: "multiple licenses with complex expressions",
			args: []SPDXLicense{{ID: "MIT AND Apache"}, {ID: "GPL-3.0-only"}},
			want: "(MIT AND Apache) AND GPL-3.0-only",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, joinLicenses(tt.args), "joinLicenses(%v)", tt.args)
		})
	}
}

func TestCreateSPDXLicenseAndGenerateLicenseID(t *testing.T) {
	tests := []struct {
		name     string
		input    pkg.License
		expected SPDXLicense
	}{
		{
			name: "SPDX expression used as ID",
			input: pkg.License{
				SPDXExpression: "MIT",
				Value:          "MIT",
				Contents:       "",
			},
			expected: SPDXLicense{
				ID:          "MIT",
				LicenseName: "MIT",
				FullText:    "NOASSERTION",
			},
		},
		{
			name: "LicenseRef with contents",
			input: pkg.License{
				Value:    "sha256:123abc",
				Contents: "license contents here",
			},
			expected: SPDXLicense{
				ID:          "LicenseRef-123abc",
				LicenseName: "sha256:123abc",
				FullText:    "license contents here",
			},
		},
		{
			name: "LicenseRef without contents",
			input: pkg.License{
				Value:    "custom-license",
				Contents: "",
			},
			expected: SPDXLicense{
				ID:          "LicenseRef-custom-license",
				LicenseName: "custom-license",
				FullText:    "NOASSERTION",
			},
		},
		{
			name: "URL is passed through",
			input: pkg.License{
				SPDXExpression: "MIT",
				URLs: []string{
					"https://example.com/license",
				},
			},
			expected: SPDXLicense{
				ID:       "MIT",
				FullText: "NOASSERTION",
				URLs:     []string{"https://example.com/license"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			license := createSPDXLicense(tt.input)
			if d := cmp.Diff(tt.expected, license); d != "" {
				t.Errorf("createSPDXLicense() mismatch (-want +got):\n%s", d)
			}
		})
	}
}
