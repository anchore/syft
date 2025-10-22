package nix

import (
	"context"
	"fmt"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

type Config struct {
	// CaptureOwnedFiles determines whether to record the list of files owned by each Nix package discovered in the store. Recording owned files provides more detailed information but increases processing time and memory usage.
	// app-config: nix.capture-owned-files
	CaptureOwnedFiles bool `json:"capture-owned-files" yaml:"capture-owned-files" mapstructure:"capture-owned-files"`
}

func (c Config) WithCaptureOwnedFiles(set bool) Config {
	c.CaptureOwnedFiles = set
	return c
}

func DefaultConfig() Config {
	return Config{
		CaptureOwnedFiles: false,
	}
}

// cataloger finds package outputs installed in the Nix store location (/nix/store/*) or in the internal nix database (/nix/var/nix/db/db.sqlite).
type cataloger struct {
	dbParser       dbCataloger
	storeCataloger storeCataloger
}

func NewCataloger(cfg Config) pkg.Cataloger {
	name := "nix-cataloger"
	return cataloger{
		dbParser:       newDBCataloger(cfg, name),
		storeCataloger: newStoreCataloger(cfg, name),
	}
}

func (c cataloger) Name() string {
	return c.dbParser.catalogerName
}

func (c cataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	// always try the DB cataloger first (based off of information recorded by actions taken by nix tooling)
	pkgs, rels, err := c.dbParser.catalog(resolver)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to catalog nix packages from database: %w", err)
	}
	if len(pkgs) > 0 {
		return pkgs, rels, nil
	}

	// there are no results from the DB cataloger, then use the store path cataloger (not as accurate / detailed in information)
	return c.storeCataloger.Catalog(ctx, resolver)
}
