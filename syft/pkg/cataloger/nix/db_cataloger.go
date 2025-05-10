package nix

import (
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

const defaultSchema = 10

type dbProcessor func(config Config, dbLocation file.Location, resolver file.Resolver, catalogerName string) ([]pkg.Package, []artifact.Relationship, error)

type dbCataloger struct {
	config          Config
	schemaProcessor map[int]dbProcessor
	catalogerName   string
}

func newDBCataloger(cfg Config, catalogerName string) dbCataloger {
	return dbCataloger{
		config:        cfg,
		catalogerName: catalogerName,
		schemaProcessor: map[int]dbProcessor{
			10: processV10DB,
		},
	}
}

type dbPackageEntry struct {
	ID    int
	DrvID int
	nixStorePath
	DeriverPath string
	*derivationFile
	Location *file.Location
	Files    []string
}

func (c dbCataloger) catalog(resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	dbLocs, err := resolver.FilesByGlob("**/nix/var/nix/db/db.sqlite")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find Nix database: %w", err)
	}

	if len(dbLocs) == 0 {
		return nil, nil, nil
	}
	var pkgs []pkg.Package
	var relationships []artifact.Relationship
	var errs error

	for _, dbLoc := range dbLocs {
		parser, schema := c.selectDBParser(dbLoc, resolver)
		if parser == nil {
			errs = unknown.Appendf(errs, dbLoc.Coordinates, "unsupported Nix database schema for schema=%d at %q", schema, dbLoc.RealPath)
			continue
		}

		newPkgs, newRelationships, err := parser(c.config, dbLoc, resolver, c.catalogerName)
		if err != nil {
			errs = unknown.Append(errs, dbLoc.Coordinates, err)
			continue
		}

		pkgs = append(pkgs, newPkgs...)
		relationships = append(relationships, newRelationships...)
	}

	return pkgs, relationships, errs
}

func (c dbCataloger) selectDBParser(dbLocation file.Location, resolver file.Resolver) (dbProcessor, int) {
	loc := resolver.RelativeFileByPath(dbLocation, path.Join(path.Dir(dbLocation.RealPath), "schema"))
	if loc == nil {
		log.WithFields("path", dbLocation.RealPath).Tracef("failed to detect Nix database schema, assuming %d", defaultSchema)
		return c.schemaProcessor[defaultSchema], 0
	}

	schemaContents, err := resolver.FileContentsByLocation(*loc)
	defer internal.CloseAndLogError(schemaContents, loc.RealPath)
	if err != nil {
		log.WithFields("path", loc.RealPath).Tracef("failed to open Nix database schema file, assuming %d", defaultSchema)
		return c.schemaProcessor[defaultSchema], 0
	}

	contents, err := io.ReadAll(schemaContents)
	if err != nil {
		log.WithFields("path", loc.RealPath).Tracef("failed to read Nix database schema file, assuming %d", defaultSchema)
		return c.schemaProcessor[defaultSchema], 0
	}

	schema, err := strconv.Atoi(strings.TrimSpace(string(contents)))
	if err != nil {
		log.WithFields("path", loc.RealPath).Tracef("failed to parse Nix database schema file, assuming %d", defaultSchema)
		return c.schemaProcessor[defaultSchema], 0
	}

	processor := c.schemaProcessor[schema]

	if processor == nil {
		closestSchema := c.findClosestSchema(schema)
		if closestSchema == 0 {
			schema = defaultSchema
		}
		processor = c.schemaProcessor[closestSchema]
		log.WithFields("path", loc.RealPath).Tracef("unsupported Nix database schema (%d), treating as closest available schema (%d)", schema, closestSchema)
	}

	return processor, schema
}

func (c dbCataloger) findClosestSchema(got int) int {
	var closest int
	var closestDiff int
	for schema := range c.schemaProcessor {
		if schema == got {
			return schema
		}
		diff := schema - got
		if diff < 0 {
			diff = -diff
		}
		if diff < closestDiff {
			closestDiff = diff
			closest = schema
		}
	}
	return closest
}
