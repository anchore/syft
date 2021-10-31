package integration

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/anchore/syft/internal/formats/syftjson"
	syftjsonModel "github.com/anchore/syft/internal/formats/syftjson/model"
	"github.com/anchore/syft/syft/sbom"
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
			catalog, _, d, src := catalogFixtureImage(t, test.fixture)

			p := syftjson.Format().Presenter(sbom.SBOM{
				Artifacts: sbom.Artifacts{
					PackageCatalog: catalog,
					Distro:         d,
				},
				Source: src.Metadata,
			})
			if p == nil {
				t.Fatal("unable to get presenter")
			}

			output := bytes.NewBufferString("")
			err := p.Present(output)
			if err != nil {
				t.Fatalf("unable to present: %+v", err)
			}

			var doc syftjsonModel.Document
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
