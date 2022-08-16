/*
Package common provides generic utilities used by multiple catalogers.
*/
package common

import (
	"fmt"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// GenericCataloger implements the Catalog interface and is responsible for dispatching the proper parser function for
// a given path or glob pattern. This is intended to be reusable across many package cataloger types.
type GenericCataloger struct {
	globParsers       map[string]ParserFn
	pathParsers       map[string]ParserFn
	postProcessors    []PostProcessFunc
	upstreamCataloger string
}

type PostProcessFunc func(resolver source.FileResolver, location source.Location, p *pkg.Package) error

// NewGenericCataloger if provided path-to-parser-function and glob-to-parser-function lookups creates a GenericCataloger
func NewGenericCataloger(pathParsers map[string]ParserFn, globParsers map[string]ParserFn, upstreamCataloger string, postProcessors ...PostProcessFunc) *GenericCataloger {
	return &GenericCataloger{
		globParsers:       globParsers,
		pathParsers:       pathParsers,
		postProcessors:    postProcessors,
		upstreamCataloger: upstreamCataloger,
	}
}

// Name returns a string that uniquely describes the upstream cataloger that this Generic Cataloger represents.
func (c *GenericCataloger) Name() string {
	return c.upstreamCataloger
}

// Catalog is given an object to resolve file references and content, this function returns any discovered Packages after analyzing the catalog source.
func (c *GenericCataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package
	var relationships []artifact.Relationship

	for location, parser := range c.selectFiles(resolver) {
		contentReader, err := resolver.FileContentsByLocation(location)
		if err != nil {
			// TODO: fail or log?
			return nil, nil, fmt.Errorf("unable to fetch contents at location=%v: %w", location, err)
		}

		discoveredPackages, discoveredRelationships, err := parser(location.RealPath, contentReader)
		internal.CloseAndLogError(contentReader, location.VirtualPath)
		if err != nil {
			// TODO: should we fail? or only log?
			log.Warnf("cataloger '%s' failed to parse entries at location=%+v: %+v", c.upstreamCataloger, location, err)
			continue
		}

		pkgsForRemoval := make(map[artifact.ID]struct{})
		var cleanedRelationships []artifact.Relationship
		for _, p := range discoveredPackages {
			p.FoundBy = c.upstreamCataloger
			p.Locations.Add(location)
			p.SetID()
			// doing it here so all packages have an ID,
			// IDs are later used to remove relationships
			if !pkg.IsValid(p) {
				pkgsForRemoval[p.ID()] = struct{}{}
				continue
			}

			for _, postProcess := range c.postProcessors {
				err = postProcess(resolver, location, p)
				if err != nil {
					return nil, nil, err
				}
			}

			packages = append(packages, *p)
		}

		cleanedRelationships = removeRelationshipsWithArtifactIDs(pkgsForRemoval, discoveredRelationships)
		relationships = append(relationships, cleanedRelationships...)
	}
	return packages, relationships, nil
}

func removeRelationshipsWithArtifactIDs(artifactsToExclude map[artifact.ID]struct{}, relationships []artifact.Relationship) []artifact.Relationship {
	if len(artifactsToExclude) == 0 || len(relationships) == 0 {
		// no removal to do
		return relationships
	}

	var cleanedRelationships []artifact.Relationship
	for _, r := range relationships {
		_, removeTo := artifactsToExclude[r.To.ID()]
		_, removaFrom := artifactsToExclude[r.From.ID()]
		if !removeTo && !removaFrom {
			cleanedRelationships = append(cleanedRelationships, r)
		}
	}

	return cleanedRelationships
}

// SelectFiles takes a set of file trees and resolves and file references of interest for future cataloging
func (c *GenericCataloger) selectFiles(resolver source.FilePathResolver) map[source.Location]ParserFn {
	var parserByLocation = make(map[source.Location]ParserFn)

	// select by exact path
	for path, parser := range c.pathParsers {
		files, err := resolver.FilesByPath(path)
		if err != nil {
			log.Warnf("cataloger failed to select files by path: %+v", err)
		}
		for _, f := range files {
			parserByLocation[f] = parser
		}
	}

	// select by glob pattern
	for globPattern, parser := range c.globParsers {
		fileMatches, err := resolver.FilesByGlob(globPattern)
		if err != nil {
			log.Warnf("failed to find files by glob: %s", globPattern)
		}
		for _, f := range fileMatches {
			parserByLocation[f] = parser
		}
	}

	return parserByLocation
}
