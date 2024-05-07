package dependency

import (
	"context"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

type catalogerDecorator struct {
	pkg.Cataloger
	resolver RelationshipResolver
}

func DecorateCatalogerWithRelationships(cataloger pkg.Cataloger, prosumer Prosumer) pkg.Cataloger {
	return &catalogerDecorator{
		Cataloger: cataloger,
		resolver:  NewRelationshipResolver(prosumer),
	}
}

func (c catalogerDecorator) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	pkgs, rels, err := c.Cataloger.Catalog(ctx, resolver)
	if err != nil {
		return nil, nil, err
	}

	rels = append(rels, c.resolver.Resolve(pkgs)...)

	return pkgs, rels, nil
}
