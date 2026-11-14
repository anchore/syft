package cpegenerate

import (
	"sort"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
)

type vendorProduct struct {
	vendor, product string
}

// opamPackageCPEs maps opam package names to the vendor/product pairs NVD uses for them. Very few OCaml packages
// have NVD CPEs, while common opam package names (fmt, re, tar, tls, unison, ...) collide with unrelated products,
// so CPEs are only generated for the packages listed here. Vulnerabilities for other opam packages are matched by
// package name (e.g. from the OCaml security advisories in OSV) rather than by CPE.
var opamPackageCPEs = map[string][]vendorProduct{
	"ocaml":               {{"ocaml", "ocaml"}, {"inria", "ocaml"}},
	"ocaml-base-compiler": {{"ocaml", "ocaml"}, {"inria", "ocaml"}},
	"ocaml-variants":      {{"ocaml", "ocaml"}, {"inria", "ocaml"}},
	"ocaml-system":        {{"ocaml", "ocaml"}, {"inria", "ocaml"}},
	"ocaml-compiler":      {{"ocaml", "ocaml"}, {"inria", "ocaml"}},
	"opam":                {{"ocaml", "opam"}},
	"opam-devel":          {{"ocaml", "opam"}},
	"opam-client":         {{"ocaml", "opam"}},
	"batteries":           {{"ocaml_batteries_project", "ocaml_batteries"}},
	"postgresql":          {{"ocaml", "postgresql-ocaml"}},
	"mysql":               {{"mysql-ocaml", "mysql-ocaml"}},
	"xml-light":           {{"nicolas_cannasse", "ocaml_xml-light_library"}},
	"camlimages":          {{"jun_furuse", "camlimages"}},
	"haxe":                {{"haxe", "haxe"}},
}

func opamCPEs(p pkg.Package) []cpe.CPE {
	var result []cpe.CPE
	for _, vp := range opamPackageCPEs[p.Name] {
		if c := newCPE(vp.product, vp.vendor, p.Version, cpe.Any); c != nil {
			result = append(result, cpe.CPE{Attributes: *c, Source: cpe.GeneratedSource})
		}
	}
	sort.Sort(cpe.BySourceThenSpecificity(result))
	return result
}
