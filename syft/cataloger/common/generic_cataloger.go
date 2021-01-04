/*
Package common provides generic utilities used by multiple catalogers.
*/
package common

import (
	"io"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// GenericCataloger implements the Catalog interface and is responsible for dispatching the proper parser function for
// a given path or glob pattern. This is intended to be reusable across many package cataloger types.
type GenericCataloger struct {
	globParsers       map[string]ParserFn
	pathParsers       map[string]ParserFn
	selectedFiles     []source.Location
	parsers           map[source.Location]ParserFn
	upstreamCataloger string
}

// NewGenericCataloger if provided path-to-parser-function and glob-to-parser-function lookups creates a GenericCataloger
func NewGenericCataloger(pathParsers map[string]ParserFn, globParsers map[string]ParserFn, upstreamCataloger string) *GenericCataloger {
	return &GenericCataloger{
		globParsers:       globParsers,
		pathParsers:       pathParsers,
		selectedFiles:     make([]source.Location, 0),
		parsers:           make(map[source.Location]ParserFn),
		upstreamCataloger: upstreamCataloger,
	}
}

// Name returns a string that uniquely describes the upstream cataloger that this Generic Cataloger represents.
func (c *GenericCataloger) Name() string {
	return c.upstreamCataloger
}

// register pairs a set of file references with a parser function for future cataloging (when the file contents are resolved)
func (c *GenericCataloger) register(files []source.Location, parser ParserFn) {
	c.selectedFiles = append(c.selectedFiles, files...)
	for _, f := range files {
		c.parsers[f] = parser
	}
}

// clear deletes all registered file-reference-to-parser-function pairings from former SelectFiles() and register() calls
func (c *GenericCataloger) clear() {
	c.selectedFiles = make([]source.Location, 0)
	c.parsers = make(map[source.Location]ParserFn)
}

// Catalog is given an object to resolve file references and content, this function returns any discovered Packages after analyzing the catalog source.
func (c *GenericCataloger) Catalog(resolver source.Resolver) ([]pkg.Package, error) {
	fileSelection := c.selectFiles(resolver)
	contents, err := resolver.MultipleFileContentsByLocation(fileSelection)
	if err != nil {
		return nil, err
	}
	return c.catalog(contents)
}

// SelectFiles takes a set of file trees and resolves and file references of interest for future cataloging
func (c *GenericCataloger) selectFiles(resolver source.FileResolver) []source.Location {
	// select by exact path
	for path, parser := range c.pathParsers {
		files, err := resolver.FilesByPath(path)
		if err != nil {
			log.Warnf("cataloger failed to select files by path: %+v", err)
		}
		if files != nil {
			c.register(files, parser)
		}
	}

	// select by glob pattern
	for globPattern, parser := range c.globParsers {
		fileMatches, err := resolver.FilesByGlob(globPattern)
		if err != nil {
			log.Warnf("failed to find files by glob: %s", globPattern)
		}
		if fileMatches != nil {
			c.register(fileMatches, parser)
		}
	}

	return c.selectedFiles
}

// catalog takes a set of file contents and uses any configured parser functions to resolve and return discovered packages
func (c *GenericCataloger) catalog(contents map[source.Location]io.ReadCloser) ([]pkg.Package, error) {
	defer c.clear()

	packages := make([]pkg.Package, 0)

	for location, parser := range c.parsers {
		content, ok := contents[location]
		if !ok {
			log.Warnf("cataloger '%s' missing file content: %+v", c.upstreamCataloger, location)
			continue
		}

		entries, err := parser(location.Path, content)
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
