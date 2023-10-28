package spdxhelpers

import (
	"strings"
	"testing"

	"github.com/spdx/tools-golang/spdx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/spdxlicense"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
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
				Licenses: pkg.NewLicenseSet(pkg.NewLicense("made-up")),
			},
			expected: expected{
				concluded: "NOASSERTION",
				declared:  "LicenseRef-made-up",
			},
		},
		{
			name: "with SPDX license",
			input: pkg.Package{
				Licenses: pkg.NewLicenseSet(pkg.NewLicense("MIT")),
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
					pkg.NewLicense("MIT"),
					pkg.NewLicense("GPL-3.0-only"),
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
					pkg.NewLicense("one thing first"),
					pkg.NewLicense("two things/#$^second"),
					pkg.NewLicense("MIT"),
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
					pkg.NewLicense("one thing first"),
					pkg.NewLicense("MIT AND GPL-3.0-only"),
					pkg.NewLicense("MIT OR APACHE-2.0"),
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

func Test_otherLicenses(t *testing.T) {
	pkg1 := pkg.Package{
		Name:    "first-pkg",
		Version: "1.1",
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicense("MIT"),
		),
	}
	pkg2 := pkg.Package{
		Name:    "second-pkg",
		Version: "2.2",
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicense("non spdx license"),
		),
	}
	bigText := `
                                 Apache License
                           Version 2.0, January 2004`
	pkg3 := pkg.Package{
		Name:    "third-pkg",
		Version: "3.3",
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicense(bigText),
		),
	}

	tests := []struct {
		name     string
		packages []pkg.Package
		expected []*spdx.OtherLicense
	}{
		{
			name:     "no other licenses when all valid spdx expressions",
			packages: []pkg.Package{pkg1},
			expected: nil,
		},
		{
			name:     "other licenses includes original text",
			packages: []pkg.Package{pkg2},
			expected: []*spdx.OtherLicense{
				{
					LicenseIdentifier: "LicenseRef-non-spdx-license",
					ExtractedText:     "non spdx license",
				},
			},
		},
		{
			name:     "big licenses get hashed",
			packages: []pkg.Package{pkg3},
			expected: []*spdx.OtherLicense{
				{
					LicenseIdentifier: "LicenseRef-e9a1e42833d3e456f147052f4d312101bd171a0798893169fe596ca6b55c049e",
					ExtractedText:     bigText,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := sbom.SBOM{
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(test.packages...),
				},
			}
			got := ToFormatModel(s)
			require.Equal(t, test.expected, got.OtherLicenses)
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

func toSpdxLicenses(ids []string) (licenses []spdxLicense) {
	for _, l := range ids {
		license := spdxLicense{id: l}
		if strings.HasPrefix(l, spdxlicense.LicenseRefPrefix) {
			license.value = l
		}
		licenses = append(licenses, license)
	}
	return licenses
}
