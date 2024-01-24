package integration

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func TestSbomCataloger(t *testing.T) {
	assertCount := func(t *testing.T, sbom sbom.SBOM, expectedGoModCatalogerPkgs int, expectedSbomCatalogerPkgs int) {
		actualSbomPkgs := 0
		actualGoModPkgs := 0

		for p := range sbom.Artifacts.Packages.Enumerate(pkg.GoModulePkg) {
			if p.FoundBy == "go-module-file-cataloger" {
				actualGoModPkgs += 1
			} else if p.FoundBy == "sbom-cataloger" {
				actualSbomPkgs += 1
			}
		}

		if actualGoModPkgs != expectedGoModCatalogerPkgs {
			t.Errorf("unexpected number of packages from go mod cataloger: %d != %d", expectedGoModCatalogerPkgs, actualGoModPkgs)
		}
		if actualSbomPkgs != expectedSbomCatalogerPkgs {
			t.Errorf("unexpected number of packages from sbom cataloger: %d != %d", expectedSbomCatalogerPkgs, actualSbomPkgs)
		}
	}

	t.Run("default catalogers", func(t *testing.T) {
		sbom, _ := catalogFixtureImage(t, "image-sbom-cataloger", source.SquashedScope, "+go-module-file-cataloger")

		expectedSbomCatalogerPkgs := 0
		expectedGoModCatalogerPkgs := 2
		assertCount(t, sbom, expectedGoModCatalogerPkgs, expectedSbomCatalogerPkgs)
	})

	// The image contains a go.mod file with 2 dependencies and an spdx json sbom.
	// The go.mod file contains 2 dependencies, and the sbom includes a go dependency
	// that overlaps with the go.mod
	t.Run("with sbom cataloger", func(t *testing.T) {
		sbom, _ := catalogFixtureImage(t, "image-sbom-cataloger", source.SquashedScope, "+go-module-file-cataloger", "+sbom-cataloger")

		expectedSbomCatalogerPkgs := 1
		expectedGoModCatalogerPkgs := 2
		assertCount(t, sbom, expectedGoModCatalogerPkgs, expectedSbomCatalogerPkgs)
	})
}
