package integration

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func catalogFixtureImage(t *testing.T, fixtureImageName string, scope source.Scope, catalogerCfg []string) (sbom.SBOM, source.Source) {
	imagetest.GetFixtureImage(t, "docker-archive", fixtureImageName)
	tarPath := imagetest.GetFixtureImageTarPath(t, fixtureImageName)
	userInput := "docker-archive:" + tarPath
	detection, err := source.Detect(userInput, source.DefaultDetectConfig())
	require.NoError(t, err)
	theSource, err := detection.NewSource(source.DefaultDetectionSourceConfig())
	require.NoError(t, err)
	t.Cleanup(func() {
		theSource.Close()
	})

	c := cataloger.DefaultConfig()
	c.Catalogers = catalogerCfg

	c.Search.Scope = scope
	pkgCatalog, relationships, actualDistro, err := syft.CatalogPackages(theSource, c)
	if err != nil {
		t.Fatalf("failed to catalog image: %+v", err)
	}

	return sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages:          pkgCatalog,
			LinuxDistribution: actualDistro,
		},
		Relationships: relationships,
		Source:        theSource.Describe(),
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

func catalogDirectory(t *testing.T, dir string) (sbom.SBOM, source.Source) {
	userInput := "dir:" + dir
	detection, err := source.Detect(userInput, source.DefaultDetectConfig())
	require.NoError(t, err)
	theSource, err := detection.NewSource(source.DefaultDetectionSourceConfig())
	require.NoError(t, err)
	t.Cleanup(func() {
		theSource.Close()
	})

	// TODO: this would be better with functional options (after/during API refactor)
	c := cataloger.DefaultConfig()
	c.Search.Scope = source.AllLayersScope
	pkgCatalog, relationships, actualDistro, err := syft.CatalogPackages(theSource, c)
	if err != nil {
		t.Fatalf("failed to catalog image: %+v", err)
	}

	return sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages:          pkgCatalog,
			LinuxDistribution: actualDistro,
		},
		Relationships: relationships,
		Source:        theSource.Describe(),
	}, theSource
}
