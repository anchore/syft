package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func TestPhotonPackageRegression(t *testing.T) { // Regression: https://github.com/anchore/syft/pull/1997
	sbom, _ := catalogFixtureImage(t, "image-photon-all-layers", source.AllLayersScope)
	var count int
	for range sbom.Artifacts.Packages.Enumerate(pkg.RpmPkg) {
		count++
	}

	assert.Greater(t, count, 0, "expected to find RPM packages in the SBOM (but did not)")
}
