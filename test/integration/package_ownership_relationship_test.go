package integration

import (
	"bytes"
	"encoding/json"
	"github.com/anchore/syft/syft/source"
	"testing"

	"github.com/anchore/syft/internal/formats/syftjson"
	syftjsonModel "github.com/anchore/syft/internal/formats/syftjson/model"
)

func TestPackageOwnershipRelationships(t *testing.T) {

	// ensure that the json encoder is applying artifact ownership with an image that has expected ownership relationships
	tests := []struct {
		fixture string
	}{
		{
			fixture: "image-owning-package",
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			sbom, _ := catalogFixtureImage(t, test.fixture, source.SquashedScope)

			output := bytes.NewBufferString("")
			err := syftjson.Format().Encode(output, sbom)
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
