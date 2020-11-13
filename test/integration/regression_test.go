// +build integration

package integration

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/source"
)

func TestRegression212ApkBufferSize(t *testing.T) {
	// This is a regression test for issue #212 (https://github.com/anchore/syft/issues/212) in which the apk db could
	// not be processed due to a scanner buffer that was too small

	fixtureImageName := "image-large-apk-data"
	_, cleanup := imagetest.GetFixtureImage(t, "docker-archive", fixtureImageName)
	tarPath := imagetest.GetFixtureImageTarPath(t, fixtureImageName)
	defer cleanup()

	catalog, _, _, err := syft.Catalog("docker-archive:"+tarPath, source.SquashedScope)
	if err != nil {
		t.Fatalf("failed to catalog image: %+v", err)
	}

	expectedPkgs := 57
	actualPkgs := 0
	for range catalog.Enumerate(pkg.ApkPkg) {
		actualPkgs += 1
	}

	if actualPkgs != expectedPkgs {
		t.Errorf("unexpected number of APK packages: %d != %d", expectedPkgs, actualPkgs)
	}
}
