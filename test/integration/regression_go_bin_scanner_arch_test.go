package integration

import (
	"strings"
	"testing"

	"github.com/anchore/syft/syft/pkg"
)

func TestRegressionGoArchDiscovery(t *testing.T) {
	const (
		expectedELFPkg   = 3
		expectedWINPkg   = 3
		expectedMACOSPkg = 3
	)
	// This is a regression test to make sure the way we detect go binary packages
	// stays consistent and reproducible as the tool chain evolves
	catalog, _, _, _ := catalogFixtureImage(t, "image-go-bin-arch-coverage")

	var actualELF, actualWIN, actualMACOS int

	for p := range catalog.Enumerate(pkg.GoModulePkg) {
		for _, l := range p.Locations {
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
