package integration

import (
	"bytes"
	"encoding/json"
	exportedPackages "github.com/anchore/syft/syft/presenter/packages"
	"testing"

	internalPackages "github.com/anchore/syft/internal/presenter/packages"
)

func TestPackageOwnershipRelationships(t *testing.T) {

	// ensure that the json presenter is applying artifact ownership with an image that has expected ownership relationships
	tests := []struct {
		fixture string
	}{
		{
			fixture: "image-owning-package",
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			catalog, d, src := catalogFixtureImage(t, test.fixture)

			p := exportedPackages.Presenter(exportedPackages.JSONPresenterOption, exportedPackages.PresenterConfig{
				SourceMetadata: src.Metadata,
				Catalog:        catalog,
				Distro:         d,
			})
			if p == nil {
				t.Fatal("unable to get presenter")
			}

			output := bytes.NewBufferString("")
			err := p.Present(output)
			if err != nil {
				t.Fatalf("unable to present: %+v", err)
			}

			var doc internalPackages.JSONDocument
			decoder := json.NewDecoder(output)
			if err := decoder.Decode(&doc); err != nil {
				t.Fatalf("unable to decode json doc: %+v", err)
			}

			if len(doc.ArtifactRelationships) == 0 {
				t.Errorf("expected to find relationships between packages but found none")
			}

		})
	}

}
