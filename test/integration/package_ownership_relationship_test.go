package integration

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/presenter"
	jsonPresenter "github.com/anchore/syft/syft/presenter/json"
	"github.com/anchore/syft/syft/source"
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
			_, cleanup := imagetest.GetFixtureImage(t, "docker-archive", test.fixture)
			tarPath := imagetest.GetFixtureImageTarPath(t, test.fixture)
			defer cleanup()

			src, catalog, d, err := syft.Catalog("docker-archive:"+tarPath, source.SquashedScope)
			if err != nil {
				t.Fatalf("failed to catalog image: %+v", err)
			}

			p := presenter.GetPresenter(presenter.JSONPresenter, src.Metadata, catalog, d)
			if p == nil {
				t.Fatal("unable to get presenter")
			}

			output := bytes.NewBufferString("")
			err = p.Present(output)
			if err != nil {
				t.Fatalf("unable to present: %+v", err)
			}

			var doc jsonPresenter.Document
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
