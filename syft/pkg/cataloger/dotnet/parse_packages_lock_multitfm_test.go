package dotnet

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

// Test_ParseDotnetPackagesLock_multiTargetFrameworkDeterministic covers a
// lockfile where the same package+version appears under more than one target
// framework with different dependency types (e.g. Direct under net8.0 but
// Transitive under netstandard2.0, which a conditional ItemGroup produces).
//
// Previously the parser collapsed these into one package by keeping whichever
// target-framework entry Go's randomized map iteration visited first, so
// scanning the same file twice could emit different `metadata.type` values.
// The reported type must now be deterministic regardless of map order.
func Test_ParseDotnetPackagesLock_multiTargetFrameworkDeterministic(t *testing.T) {
	fixture := "testdata/packages.lock-multi-tfm.json"
	fixtureLocationSet := file.NewLocationSet(file.NewLocation(fixture))

	newtonsoftPkg := pkg.Package{
		Name:      "Newtonsoft.Json",
		Version:   "13.0.3",
		PURL:      "pkg:nuget/Newtonsoft.Json@13.0.3",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetPackagesLockEntry{
			Name:        "Newtonsoft.Json",
			Version:     "13.0.3",
			ContentHash: "HrC5BXdl00IP9zeV+0Z848QWPAoCr9P3bDEZguI+gkLcBKAOxix/tLEAAHC+UvDNPv4a2d18lOReHMOagPa+zQ==",
			Type:        "Direct",
		},
	}

	expectedPkgs := []pkg.Package{newtonsoftPkg}

	var expectedRelationships []artifact.Relationship

	// run enough iterations to make randomized map iteration order in the
	// (unfixed) parser overwhelmingly likely to surface; every run must
	// produce the identical result.
	for i := 0; i < 100; i++ {
		pkgtest.TestFileParser(t, fixture, parseDotnetPackagesLock, expectedPkgs, expectedRelationships)
	}
}
