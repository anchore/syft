package integration

import (
	"testing"

	"github.com/anchore/syft/syft/source"
)

func TestRegressionJavaNoMainPackage(t *testing.T) { // Regression: https://github.com/anchore/syft/issues/252
	catalogFixtureImage(t, "image-java-no-main-package", source.SquashedScope)
}
