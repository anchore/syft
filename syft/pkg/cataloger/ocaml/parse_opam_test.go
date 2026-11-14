package ocaml

import (
	"context"
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseOpamPackage(t *testing.T) {
	fixture1 := "testdata/ocaml-base-compiler.4.14.0/opam"
	location1 := file.NewLocation(fixture1)

	fixture2 := "testdata/alcotest.opam"
	location2 := file.NewLocation(fixture2)
	ctx := context.TODO()
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
						pkg.NewLicensesFromLocationWithContext(ctx, location1, "LGPL-2.1-or-later WITH OCaml-LGPL-linking-exception")...,
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
						Dependencies: []string{
							"ocaml", "base-unix", "base-bigarray", "base-threads", "host-arch-arm32", "host-arch-arm64",
							"host-arch-ppc64", "host-arch-riscv64", "host-arch-s390x", "host-arch-x86_32", "host-arch-x86_64",
							"host-arch-unknown", "arch-x86_64", "system-mingw", "mingw-w64-shims", "system-msvc", "arch-x86_32",
							"host-system-other", "ocaml-options-vanilla", "flexdll",
						},
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
						pkg.NewLicensesFromLocationWithContext(
							ctx,
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
						Dependencies: []string{
							"dune", "ocaml", "fmt", "astring", "cmdliner", "re", "stdlib-shims", "uutf", "ocaml-syntax-shims", "odoc",
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			// dependency relationships are resolved by the cataloger's processor, not by the parser
			var expectedRelationships []artifact.Relationship

			pkgtest.TestFileParser(t, tt.fixture, parseOpamPackage, tt.want, expectedRelationships)
		})
	}
}
