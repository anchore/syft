package ocaml

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/stretchr/testify/assert"
)

func TestParseOpamPackage(t *testing.T) {
	fixture1 := "test-fixtures/ocaml-base-compiler.4.14.0/opam"
	location1 := file.NewLocation(fixture1)

	fixture2 := "test-fixtures/alcotest.opam"
	location2 := file.NewLocation(fixture2)

	tests := []struct {
		fixture string
		want    []pkg.Package
	}{
		{
			fixture: fixture1,
			want: []pkg.Package{
				{
					Name:      "ocaml-base-compiler",
					Version:   "4.14.0",
					PURL:      "pkg:opam/ocaml-base-compiler@4.14.0",
					Locations: file.NewLocationSet(location1),
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicensesFromLocation(
							location1,
							"LGPL-2.1-or-later WITH OCaml-LGPL-linking-exception",
						)...,
					),
					Language: pkg.Ocaml,
					Type:     pkg.OpamPkg,
					Metadata: pkg.OpamPackage{
						Name:     "ocaml-base-compiler",
						Version:  "4.14.0",
						Licenses: []string{"LGPL-2.1-or-later WITH OCaml-LGPL-linking-exception"},
						Homepage: "https://ocaml.org",
					},
				},
			},
		},
		{
			fixture: fixture2,
			want: []pkg.Package{
				{
					Name:      "alcotest",
					Version:   "1.5.0",
					PURL:      "pkg:opam/alcotest@1.5.0",
					Locations: file.NewLocationSet(location2),
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicensesFromLocation(
							location2,
							"ISC",
						)...,
					),
					Language: pkg.Ocaml,
					Type:     pkg.OpamPkg,
					Metadata: pkg.OpamPackage{
						Name:     "alcotest",
						Version:  "1.5.0",
						Licenses: []string{"ISC"},
						Homepage: "https://github.com/mirage/alcotest",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			// TODO: no relationships are under test yet
			var expectedRelationships []artifact.Relationship

			pkgtest.TestFileParser(t, tt.fixture, parseOpamPackage, tt.want, expectedRelationships)
		})
	}
}

func TestParseLicense(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{
			input: `"MIT"`,
			want: []string{
				"MIT",
			},
		},
		{
			input: `[
			"MIT", "IST"
			]`,
			want: []string{
				"MIT",
				"IST",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, parseLicenses(tt.input))
		})
	}
}
