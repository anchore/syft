package helpers

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/internal/spdxlicense"
	"github.com/anchore/syft/syft/pkg"
)

func Test_License(t *testing.T) {
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
				Licenses: pkg.NewLicenseSet(pkg.NewLicenseWithContext("made-up")),
			},
			expected: expected{
				concluded: "NOASSERTION",
				declared:  "LicenseRef-made-up",
			},
		},
		{
			name: "with SPDX license",
			input: pkg.Package{
				Licenses: pkg.NewLicenseSet(pkg.NewLicenseWithContext("MIT")),
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
					pkg.NewLicenseWithContext("MIT"),
					pkg.NewLicenseWithContext("GPL-3.0-only"),
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
					pkg.NewLicenseWithContext("one thing first"),
					pkg.NewLicenseWithContext("two things/#$^second"),
					pkg.NewLicenseWithContext("MIT"),
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
					pkg.NewLicenseWithContext("one thing first"),
					pkg.NewLicenseWithContext("MIT AND GPL-3.0-only"),
					pkg.NewLicenseWithContext("MIT OR APACHE-2.0"),
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
			c, d := License(test.input)
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
				Value: "MIT",
			},
			expected: spdxlicense.LicenseRefPrefix + "MIT",
		},
		{
			name: "Long value is sanitized correctly",
			license: pkg.License{
				Value: "LGPLv2+ and LGPLv2+ with exceptions and GPLv2+ and GPLv2+ with exceptions and BSD and Inner-Net and ISC and Public Domain and GFDL",
			},
			expected: spdxlicense.LicenseRefPrefix +
				"LGPLv2--and-LGPLv2--with-exceptions-and-GPLv2--and-GPLv2--with-exceptions-and-BSD-and-Inner-Net-and-ISC-and-Public-Domain-and-GFDL",
		},
		{
			name: "Uses hash of contents when nothing else is provided",
			license: pkg.License{
				Contents: "This is a very long custom license text that should be hashed because it's more than 64 characters long.",
			},
			expected: "", // We'll verify it starts with the correct prefix
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
		args []string
		want string
	}{
		{
			name: "multiple licenses",
			args: []string{"MIT", "GPL-3.0-only"},
			want: "MIT AND GPL-3.0-only",
		},
		{
			name: "multiple licenses with complex expressions",
			args: []string{"MIT AND Apache", "GPL-3.0-only"},
			want: "(MIT AND Apache) AND GPL-3.0-only",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, joinLicenses(toSpdxLicenses(tt.args)), "joinLicenses(%v)", tt.args)
		})
	}
}

func toSpdxLicenses(ids []string) (licenses []SPDXLicense) {
	for _, l := range ids {
		license := SPDXLicense{ID: l}
		if strings.HasPrefix(l, spdxlicense.LicenseRefPrefix) {
			license.Value = l
		}
		licenses = append(licenses, license)
	}
	return licenses
}
