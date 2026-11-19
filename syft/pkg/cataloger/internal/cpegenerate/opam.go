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
// package name (e.g. from the OCaml security advisories in OSV) rather than by CPE. (NVD's CPE dictionary has no
// references to opam.ocaml.org, so the generated dictionary cannot be used for opam packages.)
//
// A product is mapped from one package only, so that its vulnerabilities are not reported several times: the compiler
// from `ocaml`, which is installed with whichever of ocaml-base-compiler, ocaml-variants or ocaml-system provides it,
// and carries the plain compiler version (5.2.0 rather than 5.2.0+flambda); opam from the packages that install the
// opam binary, not from its libraries (opam-client, opam-core, ...).
var opamPackageCPEs = map[string][]vendorProduct{
	"ocaml":      {{"ocaml", "ocaml"}, {"inria", "ocaml"}},
	"opam":       {{"ocaml", "opam"}},
	"opam-devel": {{"ocaml", "opam"}},
	"batteries":  {{"ocaml_batteries_project", "ocaml_batteries"}},
	"postgresql": {{"ocaml", "postgresql-ocaml"}},
	"mysql":      {{"mysql-ocaml", "mysql-ocaml"}},
	"xml-light":  {{"nicolas_cannasse", "ocaml_xml-light_library"}},
	"camlimages": {{"jun_furuse", "camlimages"}},
	"haxe":       {{"haxe", "haxe"}},
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
