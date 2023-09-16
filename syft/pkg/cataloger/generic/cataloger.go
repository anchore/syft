package generic

import (
	"path/filepath"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
)

type processor func(resolver file.Resolver, env Environment) []request
type groupedProcessor func(resolver file.Resolver, env Environment) []groupedRequest

type request struct {
	file.Location
	Parser
}

type groupedRequest struct {
	Locations           []file.Location
	PrimaryFileLocation file.Location
	GroupedParser
}

// Cataloger implements the Catalog interface and is responsible for dispatching the proper parser function for
// a given path or glob pattern. This is intended to be reusable across many package cataloger types.
type Cataloger struct {
	processor         []processor
	upstreamCataloger string
}

// GroupedCataloger is a special case of Cataloger that will process files together
// this is needed for the case of package.json and package-lock.json files for example
type GroupedCataloger struct {
	groupedProcessor  []groupedProcessor
	upstreamCataloger string
}

func (c *GroupedCataloger) Name() string {
	return c.upstreamCataloger
}

func isPrimaryFileGlobPresent(primaryFileGlob string, globs []string) bool {
	for _, g := range globs {
		if g == primaryFileGlob {
			return true
		}
	}
	return false
}

func generateGroupedProcessor(parser GroupedParser, primaryFileGlob string, globs []string) func(resolver file.Resolver, env Environment) []groupedRequest {
	return func(resolver file.Resolver, env Environment) []groupedRequest {
		var requests []groupedRequest
		colocatedFiles := collectColocatedFiles(resolver, globs)

		// Filter to only directories that contain all specified files
		for _, files := range colocatedFiles {
			allMatched, primaryFileLocation := isAllGlobsMatched(files, globs, primaryFileGlob)
			if allMatched {
				requests = append(requests, makeGroupedRequests(parser, files, primaryFileLocation))
			}
		}

		return requests
	}
}

func collectColocatedFiles(resolver file.Resolver, globs []string) map[string][]file.Location {
	colocatedFiles := make(map[string][]file.Location)
	for _, g := range globs {
		log.WithFields("glob", g).Trace("searching for paths matching glob")
		matches, err := resolver.FilesByGlob(g)
		if err != nil {
			log.Warnf("unable to process glob=%q: %+v", g, err)
			continue
		}
		for _, match := range matches {
			dir := filepath.Dir(match.RealPath)
			colocatedFiles[dir] = append(colocatedFiles[dir], match)
		}
	}
	return colocatedFiles
}

func isAllGlobsMatched(files []file.Location, globs []string, primaryFileGlob string) (bool, file.Location) {
	globMatches := make(map[string]bool)
	var primaryFileLocation file.Location

	for _, g := range globs {
		for _, file := range files {
			if matched, _ := doublestar.PathMatch(g, file.RealPath); matched {
				if g == primaryFileGlob {
					primaryFileLocation = file
				}
				globMatches[g] = true
				break
			}
		}
	}

	return len(globMatches) == len(globs), primaryFileLocation
}

// WithParserByGlobColocation is a special case of WithParserByGlob that will only match files that are colocated
// with all of the provided globs. This is useful for cases where a package is defined by multiple files (e.g. package.json + package-lock.json).
// This function will only match files that are colocated with all of the provided globs.
func (c *GroupedCataloger) WithParserByGlobColocation(parser GroupedParser, primaryFileGlob string, globs []string) *GroupedCataloger {
	if !isPrimaryFileGlobPresent(primaryFileGlob, globs) {
		log.Warnf("primary file glob=%q not present in globs=%+v", primaryFileGlob, globs)
		return c
	}

	c.groupedProcessor = append(c.groupedProcessor, generateGroupedProcessor(parser, primaryFileGlob, globs))
	return c
}

func (c *Cataloger) WithParserByGlobs(parser Parser, globs ...string) *Cataloger {
	c.processor = append(c.processor,
		func(resolver file.Resolver, env Environment) []request {
			var requests []request
			for _, g := range globs {
				log.WithFields("glob", g).Trace("searching for paths matching glob")

				matches, err := resolver.FilesByGlob(g)
				if err != nil {
					log.Warnf("unable to process glob=%q: %+v", g, err)
					continue
				}
				requests = append(requests, makeRequests(parser, matches)...)
			}
			return requests
		},
	)
	return c
}

// selectFiles takes a set of file trees and resolves and file references of interest for future cataloging
func (c *GroupedCataloger) selectFiles(resolver file.Resolver) []groupedRequest {
	var requests []groupedRequest
	for _, proc := range c.groupedProcessor {
		requests = append(requests, proc(resolver, Environment{})...)
	}
	return requests
}

// Catalog is given an object to resolve file references and content, this function returns any discovered Packages after analyzing the catalog source.
func (c *GroupedCataloger) Catalog(resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package
	var relationships []artifact.Relationship

	logger := log.Nested("cataloger", c.upstreamCataloger)

	env := Environment{
		// TODO: consider passing into the cataloger, this would affect the cataloger interface (and all implementations). This can be deferred until later.
		LinuxRelease: linux.IdentifyRelease(resolver),
	}

	for _, req := range c.selectFiles(resolver) {
		parser := req.GroupedParser
		var readClosers []file.LocationReadCloser

		for _, location := range req.Locations {
			log.WithFields("path", location.RealPath).Trace("parsing file contents")
			contentReader, err := resolver.FileContentsByLocation(location)
			if err != nil {
				logger.WithFields("location", location.RealPath, "error", err).Warn("unable to fetch contents")
				continue
			}
			readClosers = append(readClosers, file.NewLocationReadCloser(location, contentReader))
		}

		// If your parser is expecting multiple file contents, ensure its signature reflects this change
		discoveredPackages, discoveredRelationships, err := parser(resolver, &env, readClosers)
		for _, rc := range readClosers {
			internal.CloseAndLogError(rc, rc.VirtualPath)
		}
		if err != nil {
			logger.WithFields("error", err).Warnf("cataloger failed")
			continue
		}

		for _, p := range discoveredPackages {
			p.FoundBy = c.upstreamCataloger
			packages = append(packages, p)
		}

		relationships = append(relationships, discoveredRelationships...)
	}
	return packages, relationships, nil
}

func makeGroupedRequests(parser GroupedParser, locations []file.Location, primaryFileLocation file.Location) groupedRequest {
	return groupedRequest{
		Locations:           locations,
		PrimaryFileLocation: primaryFileLocation,
		GroupedParser:       parser,
	}
}

func (c *Cataloger) WithParserByMimeTypes(parser Parser, types ...string) *Cataloger {
	c.processor = append(c.processor,
		func(resolver file.Resolver, env Environment) []request {
			var requests []request
			log.WithFields("mimetypes", types).Trace("searching for paths matching mimetype")
			matches, err := resolver.FilesByMIMEType(types...)
			if err != nil {
				log.Warnf("unable to process mimetypes=%+v: %+v", types, err)
				return nil
			}
			requests = append(requests, makeRequests(parser, matches)...)
			return requests
		},
	)
	return c
}

func (c *Cataloger) WithParserByPath(parser Parser, paths ...string) *Cataloger {
	c.processor = append(c.processor,
		func(resolver file.Resolver, env Environment) []request {
			var requests []request
			for _, p := range paths {
				log.WithFields("path", p).Trace("searching for path")

				matches, err := resolver.FilesByPath(p)
				if err != nil {
					log.Warnf("unable to process path=%q: %+v", p, err)
					continue
				}
				requests = append(requests, makeRequests(parser, matches)...)
			}
			return requests
		},
	)
	return c
}

func makeRequests(parser Parser, locations []file.Location) []request {
	var requests []request
	for _, l := range locations {
		requests = append(requests, request{
			Location: l,
			Parser:   parser,
		})
	}
	return requests
}

// NewCataloger if provided path-to-parser-function and glob-to-parser-function lookups creates a Cataloger
func NewCataloger(upstreamCataloger string) *Cataloger {
	return &Cataloger{
		upstreamCataloger: upstreamCataloger,
	}
}

func NewGroupedCataloger(upstreamCataloger string) *GroupedCataloger {
	return &GroupedCataloger{
		upstreamCataloger: upstreamCataloger,
	}
}

// Name returns a string that uniquely describes the upstream cataloger that this Generic Cataloger represents.
func (c *Cataloger) Name() string {
	return c.upstreamCataloger
}

// Catalog is given an object to resolve file references and content, this function returns any discovered Packages after analyzing the catalog source.
func (c *Cataloger) Catalog(resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package
	var relationships []artifact.Relationship

	logger := log.Nested("cataloger", c.upstreamCataloger)

	env := Environment{
		// TODO: consider passing into the cataloger, this would affect the cataloger interface (and all implementations). This can be deferred until later.
		LinuxRelease: linux.IdentifyRelease(resolver),
	}

	for _, req := range c.selectFiles(resolver) {
		location, parser := req.Location, req.Parser

		log.WithFields("path", location.RealPath).Trace("parsing file contents")

		contentReader, err := resolver.FileContentsByLocation(location)
		if err != nil {
			logger.WithFields("location", location.RealPath, "error", err).Warn("unable to fetch contents")
			continue
		}
		discoveredPackages, discoveredRelationships, err := parser(resolver, &env, file.NewLocationReadCloser(location, contentReader))
		internal.CloseAndLogError(contentReader, location.VirtualPath)
		if err != nil {
			logger.WithFields("location", location.RealPath, "error", err).Warnf("cataloger failed")
			continue
		}

		for _, p := range discoveredPackages {
			p.FoundBy = c.upstreamCataloger
			packages = append(packages, p)
		}

		relationships = append(relationships, discoveredRelationships...)
	}
	return packages, relationships, nil
}

// selectFiles takes a set of file trees and resolves and file references of interest for future cataloging
func (c *Cataloger) selectFiles(resolver file.Resolver) []request {
	var requests []request
	for _, proc := range c.processor {
		requests = append(requests, proc(resolver, Environment{})...)
	}
	return requests
}
