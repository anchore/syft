package nix

import (
	"context"
	"fmt"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

const catalogerName = "nix-cataloger"

// storeCataloger finds package outputs installed in the Nix store location (/nix/store/*) or in the internal nix database (/nix/var/nix/db/db.sqlite).
type cataloger struct {
	dbParser       dbParser
	storeCataloger pkg.Cataloger
}

func NewCataloger() pkg.Cataloger {
	return &cataloger{
		dbParser:       newDBParser(catalogerName),
		storeCataloger: NewStoreCataloger(),
	}
}

func (c *cataloger) Name() string {
	return catalogerName
}

func (c *cataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	// always try the DB cataloger first (based off if information recorded by actions taken by nix tooling)
	pkgs, rels, err := c.dbParser.parseNixDBs(resolver)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to catalog nix packages from database: %w", err)
	}
	if len(pkgs) > 0 {
		return pkgs, rels, nil
	}

	// there are no results from the DB cataloger, then use the store path cataloger (not as accurate / detailed in information)
	return c.storeCataloger.Catalog(ctx, resolver)
}
