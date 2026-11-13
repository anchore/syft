package testutil

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

// LocationsInputPackageName is the name of the package LocationsInput adds.
const LocationsInputPackageName = "example"

// LocationsInput is an SBOM with a package found at the same path in two layers and within an archive, along with
// the coordinates of the locations of that package.
func LocationsInput(t testing.TB) (sbom.SBOM, []file.Coordinates) {
	locations := []file.Coordinates{
		file.NewCoordinates("/opt/example", "sha256:layer-1"),
		file.NewCoordinates("/usr/bin/example", "sha256:layer-1"),
		file.NewCoordinates("/usr/bin/example", "sha256:layer-2"),
		{RealPath: "/app.war", FileSystemID: "sha256:layer-2", FullPath: "/app.war!/WEB-INF/lib/example.jar"},
	}

	s := DirectoryInput(t, t.TempDir())
	p := pkg.Package{Name: LocationsInputPackageName, Version: "1.0.0", Type: pkg.BinaryPkg}
	for _, c := range locations {
		p.Locations.Add(file.NewLocationFromCoordinates(c))
	}
	p.SetID()
	s.Artifacts.Packages.Add(p)

	return s, locations
}
