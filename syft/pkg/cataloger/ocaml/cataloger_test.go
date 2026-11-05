package ocaml

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_PackageCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain package files",
			fixture: "testdata/glob-paths",
			expected: []string{
				"opam/alcotest.opam",
				"opam/ocaml-base-compiler.4.14.0/opam",
				"opam/project.opam.locked",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				// parsers probe for sibling files (lock files, installed library metadata) that may not exist
				IgnoreUnfulfilledPathResponses(
					"opam/alcotest.opam.locked",
					"opam/ocaml-base-compiler.4.14.0/META",
					"opam/ocaml-base-compiler.4.14.0/dune-package",
					"opam/project.opam",
					"opam/.opam-switch/switch-state",
					"opam/ocaml-base-compiler.4.14.0/.opam-switch/switch-state",
				).
				TestCataloger(t, NewOpamPackageManagerCataloger())
		})
	}
}

func TestOpamPackageManagerCataloger_DeclaredLayouts(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromDirectory(t, "testdata/declared").
		ExpectsPackageStrings([]string{
			// the lock file supersedes foo.opam and pins the dependencies
			"foo @ 0.1.0 (project/foo.opam.locked)",
			"lwt @ 5.4.2 (project/foo.opam.locked)",
			"ocaml @ 4.14.2 (project/foo.opam.locked)",
			"ounit2 @ 2.2.5 (project/foo.opam.locked)",
			"bar @ 0.1.0 (project/bar.opam)",
			// name and version come from the file, not from a dotted directory name
			"myproj @ 1.2.3 (my-proj-1.2.3/opam)",
			// without a name field, a plain `opam` file is named after its directory
			"noname @ 2.0 (noname/opam)",
			// not cataloged: _build output, opam switch internals, opam-repository trees and installed
			// library copies (all of these carry version 9.9.9 in the fixture)
		}).
		ExpectsRelationshipStrings([]string{
			"lwt @ 5.4.2 (project/foo.opam.locked) [dependency-of] bar @ 0.1.0 (project/bar.opam)",
			"lwt @ 5.4.2 (project/foo.opam.locked) [dependency-of] foo @ 0.1.0 (project/foo.opam.locked)",
			"ocaml @ 4.14.2 (project/foo.opam.locked) [dependency-of] foo @ 0.1.0 (project/foo.opam.locked)",
			"ounit2 @ 2.2.5 (project/foo.opam.locked) [dependency-of] foo @ 0.1.0 (project/foo.opam.locked)",
		}).
		TestCataloger(t, NewOpamPackageManagerCataloger())
}

func TestOpamPackageManagerCataloger_LockFileUsesProjectMetadata(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromDirectory(t, "testdata/declared").
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, _ []artifact.Relationship) {
			for _, p := range pkgs {
				if p.Name != "foo" {
					continue
				}
				var licenses []string
				for _, l := range p.Licenses.ToSlice() {
					licenses = append(licenses, l.Value)
				}
				assert.ElementsMatch(t, []string{"MIT", "ISC"}, licenses)
				meta, ok := p.Metadata.(pkg.OpamPackage)
				require.True(t, ok)
				assert.Equal(t, "https://example.com/foo", meta.Homepage)
				assert.Equal(t, []string{"lwt", "ocaml", "ounit2"}, meta.Dependencies)
				assert.Equal(t, "pkg:opam/foo@0.1.0", p.PURL)
				return
			}
			t.Fatal("package foo not found")
		}).
		TestCataloger(t, NewOpamPackageManagerCataloger())
}

func TestOpamSwitchCataloger(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromDirectory(t, "testdata/switch").
		ExpectsPackageStrings([]string{
			"lwt @ 5.4.2 (_opam/.opam-switch/packages/lwt.5.4.2/opam)",
			"ocaml @ 4.14.2 (_opam/.opam-switch/packages/ocaml.4.14.2/opam)",
			"ocplib-endian @ 1.2 (_opam/.opam-switch/packages/ocplib-endian.1.2/opam)",
		}).
		ExpectsRelationshipStrings([]string{
			"ocaml @ 4.14.2 (_opam/.opam-switch/packages/ocaml.4.14.2/opam) [dependency-of] lwt @ 5.4.2 (_opam/.opam-switch/packages/lwt.5.4.2/opam)",
			"ocaml @ 4.14.2 (_opam/.opam-switch/packages/ocaml.4.14.2/opam) [dependency-of] ocplib-endian @ 1.2 (_opam/.opam-switch/packages/ocplib-endian.1.2/opam)",
			"ocplib-endian @ 1.2 (_opam/.opam-switch/packages/ocplib-endian.1.2/opam) [dependency-of] lwt @ 5.4.2 (_opam/.opam-switch/packages/lwt.5.4.2/opam)",
		}).
		TestCataloger(t, NewOpamSwitchCataloger())
}

func TestInstalledLibraryCataloger(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromDirectory(t, "testdata/installed-library").
		ExpectsPackageStrings([]string{
			// name and version from dune-package; license and dependencies from the sibling opam file
			"lwt @ 5.4.2 (lib/lwt/dune-package)",
			// findlib-only library: version from META
			"cmdliner @ 1.3.0 (lib/cmdliner/META)",
			// dune-package without a version: fall back to META
			"mylib @ 2.1.0 (lib/mylib/dune-package)",
			// not cataloged: findlib shims for compiler libraries (bytes, unix), non-findlib META files and
			// dune _build output
		}).
		ExpectsRelationshipStrings([]string{
			"cmdliner @ 1.3.0 (lib/cmdliner/META) [dependency-of] lwt @ 5.4.2 (lib/lwt/dune-package)",
		}).
		TestCataloger(t, NewInstalledLibraryCataloger())
}

func TestInstalledLibraryCataloger_SkipsLibrariesInsideAnOpamSwitch(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromDirectory(t, "testdata/switch").
		ExpectsPackageStrings(nil).
		TestCataloger(t, NewInstalledLibraryCataloger())
}

func TestInstalledLibraryCataloger_LicensesComeFromTheOpamFile(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromDirectory(t, "testdata/installed-library").
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, _ []artifact.Relationship) {
			for _, p := range pkgs {
				if p.Name != "lwt" {
					continue
				}
				licenses := p.Licenses.ToSlice()
				require.Len(t, licenses, 1)
				assert.Equal(t, "MIT", licenses[0].Value)
				var paths []string
				for _, l := range licenses[0].Locations.ToSlice() {
					paths = append(paths, l.RealPath)
				}
				assert.Equal(t, []string{"lib/lwt/opam"}, paths)
				return
			}
			t.Fatal("package lwt not found")
		}).
		TestCataloger(t, NewInstalledLibraryCataloger())
}
