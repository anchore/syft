package integration

import (
	"github.com/anchore/syft/syft/source"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/pkg"
)

func TestRegressionGoArchDiscovery(t *testing.T) {
	const (
		expectedELFPkg   = 4
		expectedWINPkg   = 4
		expectedMACOSPkg = 4
	)
	// This is a regression test to make sure the way we detect go binary packages
	// stays consistent and reproducible as the tool chain evolves
	sbom, _ := catalogFixtureImage(t, "image-go-bin-arch-coverage", source.SquashedScope)

	var actualELF, actualWIN, actualMACOS int

	for p := range sbom.Artifacts.PackageCatalog.Enumerate(pkg.GoModulePkg) {
		for _, l := range p.Locations.ToSlice() {
			switch {
			case strings.Contains(l.RealPath, "elf"):
				actualELF++
			case strings.Contains(l.RealPath, "win"):
				actualWIN++
			case strings.Contains(l.RealPath, "macos"):
				actualMACOS++
			default:

			}
		}
	}

	if actualELF != expectedELFPkg {
		t.Errorf("unexpected number of elf packages: %d != %d", expectedELFPkg, actualELF)
	}

	if actualWIN != expectedWINPkg {
		t.Errorf("unexpected number of win packages: %d != %d", expectedWINPkg, actualWIN)
	}

	if actualMACOS != expectedMACOSPkg {
		t.Errorf("unexpected number of macos packages: %d != %d", expectedMACOSPkg, actualMACOS)
	}
}
