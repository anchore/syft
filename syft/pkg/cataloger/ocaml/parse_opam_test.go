package ocaml

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
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
					Language: pkg.OCaml,
					Type:     pkg.OpamPkg,
					Metadata: pkg.OpamPackage{
						Name:     "ocaml-base-compiler",
						Version:  "4.14.0",
						Licenses: []string{"LGPL-2.1-or-later WITH OCaml-LGPL-linking-exception"},
						URL:      "https://github.com/ocaml/ocaml/archive/4.14.0.tar.gz",
						Checksums: []string{
							"sha256=39f44260382f28d1054c5f9d8bf4753cb7ad64027da792f7938344544da155e8",
						},
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
					Language: pkg.OCaml,
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
		name  string
		input string
		want  []string
	}{
		{
			name:  "single license",
			input: `"MIT"`,
			want: []string{
				"MIT",
			},
		},
		{
			name: "multiple license",
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
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseLicenses(tt.input))
		})
	}
}

func TestParseUrl(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantUrl       string
		wantChecksums []string
	}{
		{
			name: "single checksums",
			input: `
src:
    "https://github.com/mirage/mirage-clock/releases/download/v4.2.0/mirage-clock-4.2.0.tbz"
  checksum:
    "sha256=fa17d15d5be23c79ba741f5f7cb88ed7112de16a4410cea81c71b98086889847"
			`,
			wantUrl: "https://github.com/mirage/mirage-clock/releases/download/v4.2.0/mirage-clock-4.2.0.tbz",
			wantChecksums: []string{
				"sha256=fa17d15d5be23c79ba741f5f7cb88ed7112de16a4410cea81c71b98086889847",
			},
		},
		{
			name: "multiple checksums",
			input: `
src:
    "https://github.com/mirage/mirage-clock/releases/download/v4.2.0/mirage-clock-4.2.0.tbz"
  checksum: [
    "sha256=fa17d15d5be23c79ba741f5f7cb88ed7112de16a4410cea81c71b98086889847"
    "sha512=05a359dc8400d4ca200ff255dbd030acd33d2c4acb5020838f772c02cdb5f243f3dbafbc43a8cd51e6b5923a140f84c9e7ea25b2c0fa277bb68b996190d36e3b"
	"sha1024=05a359dc8400d4ca200ff255dbd030acd33d2c4acb5020838f772c02cdb5f243f3dbafbc43a8cd51e6b5923a140f84c9e7ea25b2c0fa277bb68b996190d36e3b"
  ]
			`,
			wantUrl: "https://github.com/mirage/mirage-clock/releases/download/v4.2.0/mirage-clock-4.2.0.tbz",
			wantChecksums: []string{
				"sha256=fa17d15d5be23c79ba741f5f7cb88ed7112de16a4410cea81c71b98086889847",
				"sha512=05a359dc8400d4ca200ff255dbd030acd33d2c4acb5020838f772c02cdb5f243f3dbafbc43a8cd51e6b5923a140f84c9e7ea25b2c0fa277bb68b996190d36e3b",
				"sha1024=05a359dc8400d4ca200ff255dbd030acd33d2c4acb5020838f772c02cdb5f243f3dbafbc43a8cd51e6b5923a140f84c9e7ea25b2c0fa277bb68b996190d36e3b",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, checksums := parseURL([]byte(tt.input))
			assert.Equal(t, tt.wantUrl, url)
			assert.Equal(t, tt.wantChecksums, checksums)
		})
	}
}
