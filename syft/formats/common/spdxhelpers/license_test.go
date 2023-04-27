package spdxhelpers

import (
	"testing"

	"github.com/stretchr/testify/assert"

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
				Licenses: []pkg.License{pkg.NewLicense("made-up")},
			},
			expected: struct{ concluded, declared string }{
				concluded: "NOASSERTION",
				declared:  "LicenseRef-made-up",
			},
		},
		{
			name: "with SPDX license",
			input: pkg.Package{
				Licenses: []pkg.License{pkg.NewLicense("MIT")},
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
					pkg.NewLicense("MIT"),
					pkg.NewLicense("GPL-3.0-only"),
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
					pkg.NewLicense("one thing first"),
					pkg.NewLicense("two things/#$^second"),
					pkg.NewLicense("MIT"),
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
		{
			name: "join parentheses correctly",
			input: pkg.Package{
				Licenses: []pkg.License{
					pkg.NewLicense("one thing first"),
					pkg.NewLicense("MIT AND GPL-3.0-only"),
					pkg.NewLicense("MIT OR APACHE-2.0"),
				},
			},
			expected: struct {
				concluded string
				declared  string
			}{
				concluded: "NOASSERTION",
				declared:  "LicenseRef-one-thing-first AND (MIT AND GPL-3.0-only) AND (MIT OR APACHE-2.0)",
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

func Test_joinLicenses1(t *testing.T) {
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
			assert.Equalf(t, tt.want, joinLicenses(tt.args), "joinLicenses(%v)", tt.args)
		})
	}
}
