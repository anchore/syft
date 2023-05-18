package integration

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func TestSbomCataloger(t *testing.T) {
	// The image contains a go.mod file with 2 dependencies and an spdx json sbom.
	// The go.mod file contains 2 dependencies, and the sbom includes a go dependency
	// that overlaps with the go.mod
	sbom, _ := catalogFixtureImage(t, "image-sbom-cataloger", source.SquashedScope, []string{"all"})

	expectedSbomCatalogerPkgs := 1
	expectedGoModCatalogerPkgs := 2
	actualSbomPkgs := 0
	actualGoModPkgs := 0
	for pkg := range sbom.Artifacts.Packages.Enumerate(pkg.GoModulePkg) {
		if pkg.FoundBy == "go-mod-file-cataloger" {
			actualGoModPkgs += 1
		} else if pkg.FoundBy == "sbom-cataloger" {
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
