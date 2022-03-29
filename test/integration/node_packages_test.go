package integration

import (
	"strings"
	"testing"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg"
)

func TestNpmPackageLockDirectory(t *testing.T) {
	sbom, _ := catalogDirectory(t, "test-fixtures/npm-lock")

	foundPackages := internal.NewStringSet()

	for actualPkg := range sbom.Artifacts.PackageCatalog.Enumerate(pkg.NpmPkg) {
		for _, actualLocation := range actualPkg.Locations.ToSlice() {
			if strings.Contains(actualLocation.RealPath, "node_modules") {
				t.Errorf("found packages from package-lock.json in node_modules: %s", actualLocation)
			}
		}
		foundPackages.Add(actualPkg.Name)
	}

	// ensure that integration test commonTestCases stay in sync with the available catalogers
	const expectedPackageCount = 6
	if len(foundPackages) != expectedPackageCount {
		t.Errorf("found the wrong set of npm package-lock.json packages (expected: %d, actual: %d)", expectedPackageCount, len(foundPackages))
	}
}

func TestYarnPackageLockDirectory(t *testing.T) {
	sbom, _ := catalogDirectory(t, "test-fixtures/yarn-lock")

	foundPackages := internal.NewStringSet()

	for actualPkg := range sbom.Artifacts.PackageCatalog.Enumerate(pkg.NpmPkg) {
		for _, actualLocation := range actualPkg.Locations.ToSlice() {
			if strings.Contains(actualLocation.RealPath, "node_modules") {
				t.Errorf("found packages from yarn.lock in node_modules: %s", actualLocation)
			}
		}
		foundPackages.Add(actualPkg.Name)
	}

	// ensure that integration test commonTestCases stay in sync with the available catalogers
	const expectedPackageCount = 5
	if len(foundPackages) != expectedPackageCount {
		t.Errorf("found the wrong set of yarn.lock packages (expected: %d, actual: %d)", expectedPackageCount, len(foundPackages))
	}
}
