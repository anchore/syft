package integration

import (
	"reflect"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func TestSbomMetadataComponent(t *testing.T) {
	sbom, _ := catalogFixtureImage(t, "image-sbom-metadata-component", source.SquashedScope, "+sbom-cataloger")

	expectedPkgs := []string{"first-subcomponent", "main-component"}
	foundPkgs := []string{}

	for sbomPkg := range sbom.Artifacts.Packages.Enumerate(pkg.JavaPkg) {
		foundPkgs = append(foundPkgs, sbomPkg.Name)
	}

	// check if both the package in `.metadata.component` and the one in `.components` were found
	if !reflect.DeepEqual(expectedPkgs, foundPkgs) {
		t.Errorf("expected packages %v, got %v", expectedPkgs, foundPkgs)
	}
}
