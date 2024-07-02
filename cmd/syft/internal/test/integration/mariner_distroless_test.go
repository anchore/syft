package integration

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func TestMarinerDistroless(t *testing.T) {
	sbom, _ := catalogFixtureImage(t, "image-mariner-distroless", source.SquashedScope)

	// 12 RPMs + 2 binaries with ELF package notes claiming to be RPMs
	expectedPkgs := 14
	actualPkgs := 0
	for range sbom.Artifacts.Packages.Enumerate(pkg.RpmPkg) {
		actualPkgs += 1
	}

	if actualPkgs != expectedPkgs {
		t.Errorf("unexpected number of RPM packages: %d != %d", expectedPkgs, actualPkgs)
	}
}
