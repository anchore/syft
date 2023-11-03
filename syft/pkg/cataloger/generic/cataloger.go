package generic

import (
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
)

type processor func(resolver file.Resolver, env Environment) []request

type request struct {
	file.Location
	Parser
}

// Cataloger implements the Catalog interface and is responsible for dispatching the proper parser function for
// a given path or glob pattern. This is intended to be reusable across many package cataloger types.
type Cataloger struct {
	processor         []processor
	upstreamCataloger string
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
		internal.CloseAndLogError(contentReader, location.AccessPath)
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
