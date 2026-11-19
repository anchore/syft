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
					".opam-switch/switch-state",
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
			// the lock file supersedes foo.opam and pins the dependencies (ounit2 is only pinned for tests)
			"foo @ 0.1.0 (project/foo.opam.locked)",
			"lwt @ 5.4.2 (project/foo.opam.locked)",
			"ocaml @ 4.14.2 (project/foo.opam.locked)",
			"bar @ 0.1.0 (project/bar.opam)",
			// name and version come from the file, not from a dotted directory name
			"myproj @ 1.2.3 (my-proj-1.2.3/opam)",
			// without a name field, a plain `opam` file is named after its directory
			"noname @ 2.0 (noname/opam)",
			// ... which may be a source archive (<name>-<version>) ...
			"cmdliner @ 1.3.0 (cmdliner-1.3.0/opam)",
			// ... or the project of an opam/ directory
			"oldstyle @ 0.3 (oldstyle/opam/opam)",
			// not cataloged: _build output, opam switch internals, opam-repository trees and installed
			// library copies (all of these carry version 9.9.9 in the fixture)
		}).
		ExpectsRelationshipStrings([]string{
			"lwt @ 5.4.2 (project/foo.opam.locked) [dependency-of] foo @ 0.1.0 (project/foo.opam.locked)",
			"ocaml @ 4.14.2 (project/foo.opam.locked) [dependency-of] foo @ 0.1.0 (project/foo.opam.locked)",
		}).
		TestCataloger(t, NewOpamPackageManagerCataloger())
}

func TestOpamPackageManagerCataloger_SwitchAtTheRoot(t *testing.T) {
	// files of an opam switch are not declared packages, also when the switch itself is scanned
	pkgtest.NewCatalogTester().
		FromDirectory(t, "testdata/declared/switch/_opam").
		ExpectsPackageStrings(nil).
		TestCataloger(t, NewOpamPackageManagerCataloger())
}

func TestOpamPackageManagerCataloger_UnnamedOpamFileAtTheRoot(t *testing.T) {
	// the scan root has no name to give the package
	pkgtest.NewCatalogTester().
		FromDirectory(t, "testdata/root-opam").
		ExpectsPackageStrings(nil).
		TestCataloger(t, NewOpamPackageManagerCataloger())
}

func TestOpamPackageManagerCataloger_RelationshipsStayWithinALockFile(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromDirectory(t, "testdata/lock-files").
		ExpectsPackageStrings([]string{
			"app @ 1.0.0 (app/app.opam.locked)",
			"lwt @ 5.4.2 (app/app.opam.locked)",
			"ocaml @ 4.14.2 (app/app.opam.locked)",
			"tool @ 2.0.0 (tool/tool.opam.locked)",
			"lwt @ 5.7.0 (tool/tool.opam.locked)",
			"ocaml @ 5.3.0 (tool/tool.opam.locked)",
		}).
		ExpectsRelationshipStrings([]string{
			"lwt @ 5.4.2 (app/app.opam.locked) [dependency-of] app @ 1.0.0 (app/app.opam.locked)",
			"ocaml @ 4.14.2 (app/app.opam.locked) [dependency-of] app @ 1.0.0 (app/app.opam.locked)",
			"lwt @ 5.7.0 (tool/tool.opam.locked) [dependency-of] tool @ 2.0.0 (tool/tool.opam.locked)",
			"ocaml @ 5.3.0 (tool/tool.opam.locked) [dependency-of] tool @ 2.0.0 (tool/tool.opam.locked)",
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
				assert.Equal(t, []string{"lwt", "ocaml"}, meta.Dependencies)
				assert.Equal(t, "pkg:opam/foo@0.1.0", p.PURL)
				return
			}
			t.Fatal("package foo not found")
		}).
		TestCataloger(t, NewOpamPackageManagerCataloger())
}

// TestPlaceholderVersions checks that unsubstituted build templates (%%VERSION%%, %%VERSION_NUM%%) are not used
// as versions.
func TestPlaceholderVersions(t *testing.T) {
	versions := func(expected map[string]string) func(t *testing.T, pkgs []pkg.Package, _ []artifact.Relationship) {
		return func(t *testing.T, pkgs []pkg.Package, _ []artifact.Relationship) {
			got := map[string]string{}
			for _, p := range pkgs {
				got[p.Name] = p.Version
			}
			assert.Equal(t, expected, got)
		}
	}

	pkgtest.NewCatalogTester().
		FromDirectory(t, "testdata/placeholder-version").
		ExpectsAssertion(versions(map[string]string{"myproj": ""})).
		TestCataloger(t, NewOpamPackageManagerCataloger())
}
