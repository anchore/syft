package integration

import (
	"testing"

	_ "modernc.org/sqlite"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func TestSqliteRpm(t *testing.T) {
	// This is a regression test for issue #469 (https://github.com/anchore/syft/issues/469). Recent RPM
	// based distribution store package data in an sqlite database
	sbom, _ := catalogFixtureImage(t, "image-sqlite-rpmdb", source.SquashedScope)

	expectedPkgs := 139
	actualPkgs := 0
	for range sbom.Artifacts.Packages.Enumerate(pkg.RpmPkg) {
		actualPkgs += 1
	}

	if actualPkgs != expectedPkgs {
		t.Errorf("unexpected number of RPM packages: %d != %d", expectedPkgs, actualPkgs)
	}
}
