package file

import (
	"fmt"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/rekor"
	"github.com/anchore/syft/syft/source"
)

// rekor-cataloger searches the Rekor transparency log for SBOMS of executable files
// found sboms are represented as external reference relationships

const catalogerName = "rekor-cataloger"

type Cataloger struct {
	client *rekor.Client
}

func NewRekorCataloger(client *rekor.Client) *Cataloger {
	return &Cataloger{client: client}
}

func (c *Cataloger) Name() string {
	return catalogerName
}

func (c *Cataloger) UsesExternalSources() bool {
	return true
}

func (c *Cataloger) Catalog(resolver source.FileResolver) ([]artifact.Relationship, error) {
	var catalogedRels []artifact.Relationship
	locations, err := resolver.FilesByMIMEType(internal.ExecutableMIMETypeSet.List()...)
	if err != nil {
		return nil, fmt.Errorf("failed to find binaries by mime types: %w", err)
	}

	if err != nil {
		return nil, fmt.Errorf("unable to get client: %w", err)
	}

	for _, location := range locations {
		rels, err := rekor.CreateRekorSbomRels(resolver, location, c.client)
		if err != nil {
			log.Debugf("Rekor cataloger failed to create relationships: %w", err)
			continue
		}
		catalogedRels = append(catalogedRels, rels...)
	}

	return catalogedRels, nil
}
