package integration

import (
	"testing"
)

func TestRegressionJavaNoMainPackage(t *testing.T) { // Regression: https://github.com/anchore/syft/issues/252
	catalogFixtureImage(t, "image-java-no-main-package")
}
