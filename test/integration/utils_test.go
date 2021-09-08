package integration

import (
	"testing"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func catalogFixtureImage(t *testing.T, fixtureImageName string) (*pkg.Catalog, *distro.Distro, *source.Source) {
	imagetest.GetFixtureImage(t, "docker-archive", fixtureImageName)
	tarPath := imagetest.GetFixtureImageTarPath(t, fixtureImageName)

	theSource, cleanupSource, err := source.New("docker-archive:"+tarPath, nil)
	t.Cleanup(cleanupSource)
	if err != nil {
		t.Fatalf("unable to get source: %+v", err)
	}

	pkgCatalog, actualDistro, err := syft.CatalogPackages(theSource, source.SquashedScope)
	if err != nil {
		t.Fatalf("failed to catalog image: %+v", err)
	}

	return pkgCatalog, actualDistro, theSource
}

func catalogDirectory(t *testing.T, dir string) (*pkg.Catalog, *distro.Distro, *source.Source) {
	theSource, cleanupSource, err := source.New("dir:"+dir, nil)
	t.Cleanup(cleanupSource)
	if err != nil {
		t.Fatalf("unable to get source: %+v", err)
	}

	pkgCatalog, actualDistro, err := syft.CatalogPackages(theSource, source.AllLayersScope)
	if err != nil {
		t.Fatalf("failed to catalog image: %+v", err)
	}

	return pkgCatalog, actualDistro, theSource
}
