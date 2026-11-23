package ocaml

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

// expectedLibraryPackage makes the package of a library of testdata/installed-library that has an opam file
// installed next to it: that file supplies the license and is supporting evidence of the package.
func expectedLibraryPackage(t *testing.T, dir, evidenceFile, name, version string, m pkg.OpamPackage) pkg.Package {
	t.Helper()
	opamLocation := file.NewLocation("testdata/installed-library/lib/" + dir + "/opam")
	return pkg.Package{
		Name:    name,
		Version: version,
		PURL:    "pkg:opam/" + name + "@" + version,
		Locations: file.NewLocationSet(
			file.NewLocation("testdata/installed-library/lib/"+dir+"/"+evidenceFile).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			opamLocation.WithoutAnnotations().WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation),
		),
		Licenses: pkg.NewLicenseSet(pkg.NewLicensesFromLocationWithContext(t.Context(), opamLocation, m.Licenses...)...),
		Language: pkg.OCaml,
		Type:     pkg.OpamPkg,
		Metadata: m,
	}
}

func TestParseDunePackage(t *testing.T) {
	fixture := "testdata/installed-library/lib/lwt/dune-package"

	// name and version come from the dune-package file; the license, homepage and dependencies from the opam file
	lwt := expectedLibraryPackage(t, "lwt", "dune-package", "lwt", "5.4.2", pkg.OpamPackage{
		Name:         "lwt",
		Version:      "5.4.2",
		Licenses:     []string{"MIT"},
		Homepage:     "https://github.com/ocsigen/lwt",
		Dependencies: []string{"ocaml", "cmdliner"},
	})

	pkgtest.NewCatalogTester().
		FromFile(t, fixture).
		FromDirectory(t, ".").
		Expects([]pkg.Package{lwt}, []artifact.Relationship(nil)).
		TestParser(t, parseDunePackage)
}

func TestParseFindlibMeta(t *testing.T) {
	fixture := "testdata/installed-library/lib/cmdliner/META"

	// the version comes from META, which the opam file next to it lacks
	cmdliner := expectedLibraryPackage(t, "cmdliner", "META", "cmdliner", "1.3.0", pkg.OpamPackage{
		Name:     "cmdliner",
		Version:  "1.3.0",
		Licenses: []string{"ISC"},
	})

	pkgtest.NewCatalogTester().
		FromFile(t, fixture).
		FromDirectory(t, ".").
		Expects([]pkg.Package{cmdliner}, []artifact.Relationship(nil)).
		TestParser(t, parseFindlibMeta)
}

func Test_corruptDunePackage(t *testing.T) {
	// not a dune-package file: no packages, and no error
	pkgtest.NewCatalogTester().
		FromFile(t, "testdata/glob-paths/lib/foo/dune-package").
		TestParser(t, parseDunePackage)
}

func Test_corruptFindlibMeta(t *testing.T) {
	// not a META file: no packages, and no error
	pkgtest.NewCatalogTester().
		FromFile(t, "testdata/glob-paths/lib/bar/META").
		TestParser(t, parseFindlibMeta)
}
