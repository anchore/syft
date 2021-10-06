/*
Package common provides generic utilities used by multiple catalogers.
*/
package common

import (
	"fmt"

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
func (c *GenericCataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, error) {
	var packages []pkg.Package
	parserByLocation := c.selectFiles(resolver)

	for location, parser := range parserByLocation {
		contentReader, err := resolver.FileContentsByLocation(location)
		if err != nil {
			// TODO: fail or log?
			return nil, fmt.Errorf("unable to fetch contents for location=%v : %w", location, err)
		}

		entries, err := parser(location.RealPath, contentReader)
		internal.CloseAndLogError(contentReader, location.VirtualPath)
		if err != nil {
			// TODO: should we fail? or only log?
			log.Warnf("cataloger '%s' failed to parse entries (location=%+v): %+v", c.upstreamCataloger, location, err)
			continue
		}

		for _, entry := range entries {
			entry.FoundBy = c.upstreamCataloger
			entry.Locations = []source.Location{location}

			packages = append(packages, entry)
		}
	}
	return packages, nil
}

// SelectFiles takes a set of file trees and resolves and file references of interest for future cataloging
func (c *GenericCataloger) selectFiles(resolver source.FilePathResolver) map[source.Location]ParserFn {
	parserByLocation := make(map[source.Location]ParserFn)

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
