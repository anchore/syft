package integration

import (
	"strings"
	"testing"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg"
)

func TestNpmPackageLockDirectory(t *testing.T) {
	catalog, _, _ := catalogDirectory(t, "test-fixtures/npm-lock")

	foundPackages := internal.NewStringSet()

	for actualPkg := range catalog.Enumerate(pkg.NpmPkg) {
		for _, actualLocation := range actualPkg.Locations {
			if strings.Contains(actualLocation.RealPath, "node_modules") {
				t.Errorf("found packages from package-lock.json in node_modules: %s", actualLocation)
			}
		}
		foundPackages.Add(actualPkg.Name)
	}

	// ensure that integration test commonTestCases stay in sync with the available catalogers
	if len(foundPackages) != 6 {
		t.Errorf("found the wrong set of npm package-lock.json packages %d != %d", len(foundPackages), 6)
	}
}

func TestYarnPackageLockDirectory(t *testing.T) {
	catalog, _, _ := catalogDirectory(t, "test-fixtures/yarn-lock")

	foundPackages := internal.NewStringSet()

	for actualPkg := range catalog.Enumerate(pkg.NpmPkg) {
		for _, actualLocation := range actualPkg.Locations {
			if strings.Contains(actualLocation.RealPath, "node_modules") {
				t.Errorf("found packages from yarn.lock in node_modules: %s", actualLocation)
			}
		}
		foundPackages.Add(actualPkg.Name)
	}

	// ensure that integration test commonTestCases stay in sync with the available catalogers
	if len(foundPackages) != 5 {
		t.Errorf("found the wrong set of yarn.lock packages %d != %d", len(foundPackages), 5)
	}
}
