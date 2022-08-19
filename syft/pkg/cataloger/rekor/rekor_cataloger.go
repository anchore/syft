package rekor

import (
	"fmt"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	rekorLib "github.com/anchore/syft/syft/rekor"
	"github.com/anchore/syft/syft/source"
)

// rekor-cataloger searches the Rekor transparency log for SBOMS of executable files
// found sboms are represented as external reference relationships

const catalogerName = "rekor-cataloger"

type Cataloger struct{}

func NewRekorCataloger() *Cataloger {
	return &Cataloger{}
}

func (c *Cataloger) Name() string {
	return catalogerName
}

func (c *Cataloger) UsesExternalSources() bool {
	return true
}

func (c *Cataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
	var catalogedRels []artifact.Relationship
	locations, err := resolver.FilesByMIMEType(internal.ExecutableMIMETypeSet.List()...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find binaries by mime types: %w", err)
	}

	client, err := rekorLib.NewClient()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get client: %w", err)
	}

	for _, location := range locations {
		rels, err := rekorLib.CreateRekorSbomRels(resolver, location, client)
		if err != nil {
			log.Debugf("Rekor cataloger failed to create relationships: %w", err)
			continue
		}
		catalogedRels = append(catalogedRels, rels...)
	}

	return nil, catalogedRels, nil
}
