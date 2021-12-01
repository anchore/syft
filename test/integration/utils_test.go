package integration

import (
	"testing"

	"github.com/anchore/syft/syft/sbom"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/source"
)

func catalogFixtureImage(t *testing.T, fixtureImageName string) (sbom.SBOM, *source.Source) {
	imagetest.GetFixtureImage(t, "docker-archive", fixtureImageName)
	tarPath := imagetest.GetFixtureImageTarPath(t, fixtureImageName)

	theSource, cleanupSource, err := source.New("docker-archive:"+tarPath, nil)
	t.Cleanup(cleanupSource)
	if err != nil {
		t.Fatalf("unable to get source: %+v", err)
	}

	pkgCatalog, relationships, actualDistro, err := syft.CatalogPackages(theSource, source.SquashedScope)
	if err != nil {
		t.Fatalf("failed to catalog image: %+v", err)
	}

	return sbom.SBOM{
		Artifacts: sbom.Artifacts{
			PackageCatalog: pkgCatalog,
			Distro:         actualDistro,
		},
		Relationships: relationships,
		Source:        theSource.Metadata,
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: "v0.42.0-bogus",
			// the application configuration should be persisted here, however, we do not want to import
			// the application configuration in this package (it's reserved only for ingestion by the cmd package)
			Configuration: map[string]string{
				"config-key": "config-value",
			},
		},
	}, theSource
}

func catalogDirectory(t *testing.T, dir string) (sbom.SBOM, *source.Source) {
	theSource, cleanupSource, err := source.New("dir:"+dir, nil)
	t.Cleanup(cleanupSource)
	if err != nil {
		t.Fatalf("unable to get source: %+v", err)
	}

	pkgCatalog, relationships, actualDistro, err := syft.CatalogPackages(theSource, source.AllLayersScope)
	if err != nil {
		t.Fatalf("failed to catalog image: %+v", err)
	}

	return sbom.SBOM{
		Artifacts: sbom.Artifacts{
			PackageCatalog: pkgCatalog,
			Distro:         actualDistro,
		},
		Relationships: relationships,
		Source:        theSource.Metadata,
	}, theSource
}
