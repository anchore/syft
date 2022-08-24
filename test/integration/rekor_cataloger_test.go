package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/rekor"
	"github.com/anchore/syft/syft/source"
)

func TestRekorCataloger(t *testing.T) {
	sbom, _ := catalogFixtureImage(t, "image-rekor", source.SquashedScope, []string{"all"})

	expectedExternalRelationships := 1
	var foundExternalRelationship artifact.Relationship
	foundExternalRelationships := 0
	for _, rel := range sbom.Relationships {
		if _, ok := rel.To.(rekor.ExternalRef); ok {
			foundExternalRelationships += 1
			foundExternalRelationship = rel
		}
	}
	assert.Equal(t, expectedExternalRelationships, foundExternalRelationships)

	if foundExternalRelationships > 0 {
		// assert that the found external relationship is FROM a coordinates. spdx22json/to_format_model.go depends on this
		if _, ok := foundExternalRelationship.From.(source.Coordinates); !ok {
			assert.FailNow(t, "the rekor-cataloger surfaced a relationship that is not FROM a coordinates")
		}
	}

}
