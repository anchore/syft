/*
Package common provides generic utilities used by multiple catalogers.
*/
package common

import (
	"fmt"

	"github.com/anchore/syft/syft/artifact"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// GenericCataloger implements the Catalog interface and is responsible for dispatching the proper parser function for
// a given path or glob pattern. This is intended to be reusable across many package cataloger types.
type GenericCataloger struct {
	globParsers       map[string]ParserFn
	pathParsers       map[string]ParserFn
	upstreamCataloger string
}

// NewGenericCataloger if provided path-to-parser-function and glob-to-parser-function lookups creates a GenericCataloger
func NewGenericCataloger(pathParsers map[string]ParserFn, globParsers map[string]ParserFn, upstreamCataloger string) *GenericCataloger {
	return &GenericCataloger{
		globParsers:       globParsers,
		pathParsers:       pathParsers,
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

		for _, p := range discoveredPackages {
			p.FoundBy = c.upstreamCataloger
			p.Locations.Add(location)
			p.SetID()
			packages = append(packages, *p)
		}

		relationships = append(relationships, discoveredRelationships...)
	}
	return packages, relationships, nil
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
