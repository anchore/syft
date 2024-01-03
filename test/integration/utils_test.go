package integration

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/clio"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func catalogFixtureImage(t *testing.T, fixtureImageName string, scope source.Scope, catalogerSelection ...string) (sbom.SBOM, source.Source) {
	// get the fixture image tar file
	imagetest.GetFixtureImage(t, "docker-archive", fixtureImageName)
	tarPath := imagetest.GetFixtureImageTarPath(t, fixtureImageName)
	userInput := "docker-archive:" + tarPath

	// get the source to build an SBOM against
	detection, err := source.Detect(userInput, source.DefaultDetectConfig())
	require.NoError(t, err)

	theSource, err := detection.NewSource(source.DefaultDetectionSourceConfig())
	require.NoError(t, err)

	t.Cleanup(func() {
		theSource.Close()
	})

	// build the SBOM
	cfg := options.DefaultCatalog().ToSBOMConfig(clio.Identification{
		Name:    "syft-tester",
		Version: "v0.99.0",
	}).WithCatalogerSelection(
		pkgcataloging.NewSelectionRequest().
			WithDefaults(pkgcataloging.ImageTag).
			WithExpression(catalogerSelection...),
	)
	cfg.Search.Scope = scope

	s, err := syft.CreateSBOM(theSource, cfg)

	require.NoError(t, err)
	require.NotNil(t, s)

	return *s, theSource
}

func catalogDirectory(t *testing.T, dir string, catalogerSelection ...string) (sbom.SBOM, source.Source) {
	// get the source to build an sbom against
	userInput := "dir:" + dir
	detection, err := source.Detect(userInput, source.DefaultDetectConfig())
	require.NoError(t, err)

	theSource, err := detection.NewSource(source.DefaultDetectionSourceConfig())
	require.NoError(t, err)
	t.Cleanup(func() {
		theSource.Close()
	})

	// build the SBOM
	cfg := options.DefaultCatalog().ToSBOMConfig(clio.Identification{
		Name:    "syft-tester",
		Version: "v0.99.0",
	}).WithCatalogerSelection(
		pkgcataloging.NewSelectionRequest().
			WithDefaults(pkgcataloging.DirectoryTag).
			WithExpression(catalogerSelection...),
	)
	s, err := syft.CreateSBOM(theSource, cfg)

	require.NoError(t, err)
	require.NotNil(t, s)

	return *s, theSource
}
