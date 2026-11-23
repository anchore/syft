package ocaml

import (
	"context"
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseOpamLockFile(t *testing.T) {
	fixture := "testdata/lock-files/app/app.opam.locked"
	location := file.NewLocation(fixture)

	app := pkg.Package{
		Name:      "app",
		Version:   "1.0.0",
		PURL:      "pkg:opam/app@1.0.0",
		Locations: file.NewLocationSet(location),
		Licenses:  pkg.NewLicenseSet(),
		Language:  pkg.OCaml,
		Type:      pkg.OpamPkg,
		Metadata: pkg.OpamPackage{
			Name:         "app",
			Version:      "1.0.0",
			Dependencies: []string{"lwt", "ocaml"},
		},
	}
	lwt := pkg.Package{
		Name:      "lwt",
		Version:   "5.4.2",
		PURL:      "pkg:opam/lwt@5.4.2",
		Locations: file.NewLocationSet(location),
		Licenses:  pkg.NewLicenseSet(),
		Language:  pkg.OCaml,
		Type:      pkg.OpamPkg,
		Metadata: pkg.OpamPackage{
			Name:    "lwt",
			Version: "5.4.2",
		},
	}
	ocaml := pkg.Package{
		Name:      "ocaml",
		Version:   "4.14.2",
		PURL:      "pkg:opam/ocaml@4.14.2",
		Locations: file.NewLocationSet(location),
		Licenses:  pkg.NewLicenseSet(),
		Language:  pkg.OCaml,
		Type:      pkg.OpamPkg,
		Metadata: pkg.OpamPackage{
			Name:    "ocaml",
			Version: "4.14.2",
		},
	}

	expectedPkgs := []pkg.Package{app, lwt, ocaml}
	expectedRelationships := []artifact.Relationship{
		{From: lwt, To: app, Type: artifact.DependencyOfRelationship},
		{From: ocaml, To: app, Type: artifact.DependencyOfRelationship},
	}

	pkgtest.TestFileParser(t, fixture, parseOpamLockFile, expectedPkgs, expectedRelationships)
}

func TestParseOpamLockFile_ProjectMetadataFromTheOpamFile(t *testing.T) {
	fixture := "testdata/declared/project/foo.opam.locked"
	location := file.NewLocation(fixture)
	opamLocation := file.NewLocation("testdata/declared/project/foo.opam")
	ctx := context.TODO()

	// the lock file leaves out the license and homepage, which the opam file next to it has; ounit2 is pinned for the
	// tests only, so it is neither a package nor a dependency
	foo := pkg.Package{
		Name:      "foo",
		Version:   "0.1.0",
		PURL:      "pkg:opam/foo@0.1.0",
		Locations: file.NewLocationSet(location),
		Licenses:  pkg.NewLicenseSet(pkg.NewLicensesFromLocationWithContext(ctx, opamLocation, "MIT", "ISC")...),
		Language:  pkg.OCaml,
		Type:      pkg.OpamPkg,
		Metadata: pkg.OpamPackage{
			Name:         "foo",
			Version:      "0.1.0",
			Licenses:     []string{"MIT", "ISC"},
			Homepage:     "https://example.com/foo",
			Dependencies: []string{"lwt", "ocaml"},
		},
	}
	lwt := pkg.Package{
		Name:      "lwt",
		Version:   "5.4.2",
		PURL:      "pkg:opam/lwt@5.4.2",
		Locations: file.NewLocationSet(location),
		Licenses:  pkg.NewLicenseSet(),
		Language:  pkg.OCaml,
		Type:      pkg.OpamPkg,
		Metadata:  pkg.OpamPackage{Name: "lwt", Version: "5.4.2"},
	}
	ocaml := pkg.Package{
		Name:      "ocaml",
		Version:   "4.14.2",
		PURL:      "pkg:opam/ocaml@4.14.2",
		Locations: file.NewLocationSet(location),
		Licenses:  pkg.NewLicenseSet(),
		Language:  pkg.OCaml,
		Type:      pkg.OpamPkg,
		Metadata:  pkg.OpamPackage{Name: "ocaml", Version: "4.14.2"},
	}

	pkgtest.NewCatalogTester().
		FromFile(t, fixture).
		FromDirectory(t, ".").
		Expects(
			[]pkg.Package{foo, lwt, ocaml},
			[]artifact.Relationship{
				{From: lwt, To: foo, Type: artifact.DependencyOfRelationship},
				{From: ocaml, To: foo, Type: artifact.DependencyOfRelationship},
			},
		).
		TestParser(t, parseOpamLockFile)
}

func Test_corruptOpamLockFile(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "testdata/glob-paths/opam/project.opam.locked").
		WithError().
		TestParser(t, parseOpamLockFile)
}

func Test_truncatedOpamLockFile(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "testdata/corrupt/foo.opam.locked").
		WithError().
		TestParser(t, parseOpamLockFile)
}
