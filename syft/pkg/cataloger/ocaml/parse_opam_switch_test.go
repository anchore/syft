package ocaml

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseOpamSwitchState(t *testing.T) {
	fixture := "testdata/switch/_opam/.opam-switch/switch-state"
	stateLocation := file.NewLocation(fixture).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation)
	recordPath := func(nameVersion string) string {
		return "testdata/switch/_opam/.opam-switch/packages/" + nameVersion + "/opam"
	}
	record := func(nameVersion string) file.Location {
		return file.NewLocation(recordPath(nameVersion)).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)
	}
	newPkg := func(name, version string, locations file.LocationSet, m pkg.OpamPackage) pkg.Package {
		return pkg.Package{
			Name:      name,
			Version:   version,
			PURL:      "pkg:opam/" + name + "@" + version,
			Locations: locations,
			Licenses:  pkg.NewLicenseSet(),
			Language:  pkg.OCaml,
			Type:      pkg.OpamPkg,
			Metadata:  m,
		}
	}

	// the package record of an installed package is its primary evidence and the switch state supports it
	lwt := newPkg("lwt", "5.4.2", file.NewLocationSet(record("lwt.5.4.2"), stateLocation), pkg.OpamPackage{
		Name:         "lwt",
		Version:      "5.4.2",
		Licenses:     []string{"MIT"},
		URL:          "https://github.com/ocsigen/lwt/archive/refs/tags/5.4.2.tar.gz",
		Checksums:    []string{"md5=00000000000000000000000000000000"},
		Homepage:     "https://github.com/ocsigen/lwt",
		Dependencies: []string{"dune", "ocaml", "ocplib-endian"},
	})
	lwt.Licenses = pkg.NewLicenseSet(pkg.NewLicensesFromLocationWithContext(t.Context(), record("lwt.5.4.2"), "MIT")...)
	ocaml := newPkg("ocaml", "4.14.2", file.NewLocationSet(record("ocaml.4.14.2"), stateLocation), pkg.OpamPackage{
		Name:     "ocaml",
		Version:  "4.14.2",
		Licenses: []string{"LGPL-2.1-or-later WITH OCaml-LGPL-linking-exception"},
	})
	ocaml.Licenses = pkg.NewLicenseSet(pkg.NewLicensesFromLocationWithContext(t.Context(), record("ocaml.4.14.2"), "LGPL-2.1-or-later WITH OCaml-LGPL-linking-exception")...)
	endian := newPkg("ocplib-endian", "1.2", file.NewLocationSet(record("ocplib-endian.1.2"), stateLocation), pkg.OpamPackage{
		Name:         "ocplib-endian",
		Version:      "1.2",
		Licenses:     []string{"LGPL-2.1-only WITH OCaml-LGPL-linking-exception"},
		Dependencies: []string{"ocaml"},
	})
	endian.Licenses = pkg.NewLicenseSet(pkg.NewLicensesFromLocationWithContext(t.Context(), record("ocplib-endian.1.2"), "LGPL-2.1-only WITH OCaml-LGPL-linking-exception")...)
	// installed without a package record: known from the switch state only
	baseUnix := newPkg("base-unix", "base", file.NewLocationSet(file.NewLocation(fixture)), pkg.OpamPackage{
		Name:    "base-unix",
		Version: "base",
	})

	pkgtest.NewCatalogTester().
		FromFile(t, fixture).
		FromDirectory(t, ".").
		Expects(
			[]pkg.Package{baseUnix, lwt, ocaml, endian},
			[]artifact.Relationship{
				{From: ocaml, To: lwt, Type: artifact.DependencyOfRelationship},
				{From: endian, To: lwt, Type: artifact.DependencyOfRelationship},
				{From: ocaml, To: endian, Type: artifact.DependencyOfRelationship},
			},
		).
		TestParser(t, parseOpamSwitchState)
}

func Test_corruptOpamSwitchState(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "testdata/glob-paths/switch/.opam-switch/switch-state").
		WithError().
		TestParser(t, parseOpamSwitchState)
}
