package integration

import (
	"bytes"
	"testing"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/presenter/json"
	"github.com/anchore/syft/syft/scope"
	"github.com/go-test/deep"
)

func TestCatalogFromJSON(t *testing.T) {

	// ensure each of our fixture images results in roughly the same shape when:
	//     generate json -> import json -> assert packages and distro are the same (except for select fields)

	tests := []struct {
		fixture string
	}{
		{
			fixture: "image-pkg-coverage",
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			_, cleanup := imagetest.GetFixtureImage(t, "docker-archive", test.fixture)
			tarPath := imagetest.GetFixtureImageTarPath(t, test.fixture)
			defer cleanup()

			expectedCatalog, s, expectedDistro, err := syft.Catalog("docker-archive:"+tarPath, scope.AllLayersScope)
			if err != nil {
				t.Fatalf("failed to catalog image: %+v", err)
			}

			var buf bytes.Buffer
			jsonPres := json.NewPresenter(expectedCatalog, *s, *expectedDistro)
			if err = jsonPres.Present(&buf); err != nil {
				t.Fatalf("failed to write to presenter: %+v", err)
			}

			// TODO: test img

			actualCatalog, actualDistro, err := syft.CatalogFromJSON(&buf)
			if err != nil {
				t.Fatalf("failed to import document: %+v", err)
			}

			for _, d := range deep.Equal(actualDistro, expectedDistro) {
				t.Errorf("   distro diff: %+v", d)
			}

			var actualPackages, expectedPackages []*pkg.Package

			// TODO: take out pkg.RpmdbMetadataType filter

			for _, p := range expectedCatalog.Sorted() {
				expectedPackages = append(expectedPackages, p)
			}

			for _, p := range actualCatalog.Sorted() {
				actualPackages = append(actualPackages, p)
			}

			if len(actualPackages) != len(expectedPackages) {
				t.Fatalf("mismatched package length: %d != %d", len(actualPackages), len(expectedPackages))
			}

			for i, e := range expectedPackages {
				a := actualPackages[i]

				// omit fields that should be missing
				e.Source = nil
				e.FoundBy = ""
				if e.MetadataType == pkg.JavaMetadataType {
					metadata := e.Metadata.(pkg.JavaMetadata)
					metadata.Parent = nil
					e.Metadata = metadata
				}

				for _, d := range deep.Equal(a, e) {
					t.Errorf("   package %d (name=%s) diff: %+v", i, e.Name, d)
				}
			}

		})
	}

}
