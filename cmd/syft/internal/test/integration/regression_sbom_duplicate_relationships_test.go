package integration

import (
	"fmt"
	"testing"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/source"
)

func TestRelationshipsUnique(t *testing.T) {
	// This test is to ensure that the relationships are deduplicated in the final SBOM.
	// It is not a test of the relationships themselves.
	// This test is a regression test for #syft/2509
	sbom, _ := catalogFixtureImage(t, "image-pkg-coverage", source.SquashedScope)
	observedRelationships := strset.New()

	for _, rel := range sbom.Relationships {
		unique := fmt.Sprintf("%s:%s:%s", rel.From.ID(), rel.To.ID(), rel.Type)
		if observedRelationships.Has(unique) {
			t.Errorf("duplicate relationship found: %s", unique)
		}
		observedRelationships.Add(unique)
	}
}
