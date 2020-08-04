// +build integration

package integration

import (
	"testing"

	"github.com/anchore/syft/syft"

	"github.com/anchore/syft/internal"

	"github.com/anchore/go-testutils"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

func TestPkgCoverageImage(t *testing.T) {
	fixtureImageName := "image-pkg-coverage"
	_, cleanup := testutils.GetFixtureImage(t, "docker-archive", fixtureImageName)
	tarPath := testutils.GetFixtureImageTarPath(t, fixtureImageName)
	defer cleanup()

	catalog, _, _, err := syft.Catalog("docker-archive://"+tarPath, scope.AllLayersScope)
	if err != nil {
		t.Fatalf("failed to catalog image: %+v", err)
	}

	observedLanguages := internal.NewStringSet()
	definedLanguages := internal.NewStringSet()
	for _, l := range pkg.AllLanguages {
		definedLanguages.Add(l.String())
	}

	observedPkgs := internal.NewStringSet()
	definedPkgs := internal.NewStringSet()
	for _, p := range pkg.AllPkgs {
		definedPkgs.Add(string(p))
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pkgCount := 0

			for a := range catalog.Enumerate(c.pkgType) {

				observedLanguages.Add(a.Language.String())
				observedPkgs.Add(string(a.Type))

				expectedVersion, ok := c.pkgInfo[a.Name]
				if !ok {
					t.Errorf("unexpected package found: %s", a.Name)
				}

				if expectedVersion != a.Version {
					t.Errorf("unexpected package version (pkg=%s): %s, expected: %s", a.Name, a.Version, expectedVersion)
				}

				if a.Language != c.pkgLanguage {
					t.Errorf("bad language (pkg=%+v): %+v", a.Name, a.Language)
				}

				if a.Type != c.pkgType {
					t.Errorf("bad package type (pkg=%+v): %+v", a.Name, a.Type)
				}
				pkgCount++
			}

			if pkgCount != len(c.pkgInfo) {
				for a := range catalog.Enumerate(c.pkgType) {
					t.Log("   ", a)
				}
				t.Fatalf("unexpected package count: %d!=%d", pkgCount, len(c.pkgInfo))
			}

		})
	}

	observedLanguages.Remove(pkg.UnknownLanguage.String())
	definedLanguages.Remove(pkg.UnknownLanguage.String())
	observedPkgs.Remove(string(pkg.UnknownPkg))
	definedPkgs.Remove(string(pkg.UnknownPkg))

	// ensure that integration test cases stay in sync with the available catalogers
	if len(observedLanguages) < len(definedLanguages) {
		t.Errorf("language coverage incomplete (languages=%d, coverage=%d)", len(definedLanguages), len(observedLanguages))
	}

	if len(observedPkgs) < len(definedPkgs) {
		t.Errorf("package coverage incomplete (packages=%d, coverage=%d)", len(definedPkgs), len(observedPkgs))
	}
}

func TestPkgCoverageDirectory(t *testing.T) {
	catalog, _, _, err := syft.Catalog("dir://test-fixtures/image-pkg-coverage", scope.AllLayersScope)

	if err != nil {
		t.Errorf("unable to create scope from dir: %+v", err)
	}

	observedLanguages := internal.NewStringSet()
	definedLanguages := internal.NewStringSet()
	for _, l := range pkg.AllLanguages {
		definedLanguages.Add(l.String())
	}

	observedPkgs := internal.NewStringSet()
	definedPkgs := internal.NewStringSet()
	for _, p := range pkg.AllPkgs {
		definedPkgs.Add(string(p))
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pkgCount := 0

			for a := range catalog.Enumerate(c.pkgType) {

				observedLanguages.Add(a.Language.String())
				observedPkgs.Add(string(a.Type))

				expectedVersion, ok := c.pkgInfo[a.Name]
				if !ok {
					t.Errorf("unexpected package found: %s", a.Name)
				}

				if expectedVersion != a.Version {
					t.Errorf("unexpected package version (pkg=%s): %s", a.Name, a.Version)
				}

				if a.Language != c.pkgLanguage {
					t.Errorf("bad language (pkg=%+v): %+v", a.Name, a.Language)
				}

				if a.Type != c.pkgType {
					t.Errorf("bad package type (pkg=%+v): %+v", a.Name, a.Type)
				}
				pkgCount++
			}

			if pkgCount != len(c.pkgInfo) {
				for a := range catalog.Enumerate(c.pkgType) {
					t.Log("   ", a)
				}
				t.Fatalf("unexpected package count: %d!=%d", pkgCount, len(c.pkgInfo))
			}

		})
	}

	observedLanguages.Remove(pkg.UnknownLanguage.String())
	definedLanguages.Remove(pkg.UnknownLanguage.String())
	observedPkgs.Remove(string(pkg.UnknownPkg))
	definedPkgs.Remove(string(pkg.UnknownPkg))

	// ensure that integration test cases stay in sync with the available catalogers
	if len(observedLanguages) < len(definedLanguages) {
		t.Errorf("language coverage incomplete (languages=%d, coverage=%d)", len(definedLanguages), len(observedLanguages))
	}

	if len(observedPkgs) < len(definedPkgs) {
		t.Errorf("package coverage incomplete (packages=%d, coverage=%d)", len(definedPkgs), len(observedPkgs))
	}
}
