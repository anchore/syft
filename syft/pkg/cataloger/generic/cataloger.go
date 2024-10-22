package generic

import (
	"context"

	"github.com/anchore/go-logger"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
)

// Processor is a function that can filter or augment existing packages and relationships based on existing material.
type Processor func([]pkg.Package, []artifact.Relationship, error) ([]pkg.Package, []artifact.Relationship, error)

// ResolvingProcessor is a Processor with the additional behavior of being able to reference additional material from a file resolver.
type ResolvingProcessor func(context.Context, file.Resolver, []pkg.Package, []artifact.Relationship, error) ([]pkg.Package, []artifact.Relationship, error)

type requester func(resolver file.Resolver, env Environment) []request

type request struct {
	file.Location
	Parser
}

type processExecutor interface {
	process(ctx context.Context, resolver file.Resolver, pkgs []pkg.Package, rels []artifact.Relationship, err error) ([]pkg.Package, []artifact.Relationship, error)
}

type processorWrapper struct {
	Processor
}

func (p processorWrapper) process(_ context.Context, _ file.Resolver, pkgs []pkg.Package, rels []artifact.Relationship, err error) ([]pkg.Package, []artifact.Relationship, error) {
	return p.Processor(pkgs, rels, err)
}

type resolvingProcessorWrapper struct {
	ResolvingProcessor
}

func (p resolvingProcessorWrapper) process(ctx context.Context, resolver file.Resolver, pkgs []pkg.Package, rels []artifact.Relationship, err error) ([]pkg.Package, []artifact.Relationship, error) {
	return p.ResolvingProcessor(ctx, resolver, pkgs, rels, err)
}

// Cataloger implements the Catalog interface and is responsible for dispatching the proper parser function for
// a given path or glob pattern. This is intended to be reusable across many package cataloger types.
type Cataloger struct {
	processors        []processExecutor
	requesters        []requester
	upstreamCataloger string
}

func (c *Cataloger) WithParserByGlobs(parser Parser, globs ...string) *Cataloger {
	c.requesters = append(c.requesters,
		func(resolver file.Resolver, _ Environment) []request {
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
	c.requesters = append(c.requesters,
		func(resolver file.Resolver, _ Environment) []request {
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
	c.requesters = append(c.requesters,
		func(resolver file.Resolver, _ Environment) []request {
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

func (c *Cataloger) WithProcessors(processors ...Processor) *Cataloger {
	for _, p := range processors {
		c.processors = append(c.processors, processorWrapper{Processor: p})
	}
	return c
}

func (c *Cataloger) WithResolvingProcessors(processors ...ResolvingProcessor) *Cataloger {
	for _, p := range processors {
		c.processors = append(c.processors, resolvingProcessorWrapper{ResolvingProcessor: p})
	}
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
func (c *Cataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package
	var relationships []artifact.Relationship
	var errs error

	lgr := log.Nested("cataloger", c.upstreamCataloger)

	env := Environment{
		// TODO: consider passing into the cataloger, this would affect the cataloger interface (and all implementations). This can be deferred until later.
		LinuxRelease: linux.IdentifyRelease(resolver),
	}

	for _, req := range c.selectFiles(resolver) {
		location, parser := req.Location, req.Parser

		log.WithFields("path", location.RealPath).Trace("parsing file contents")

		discoveredPackages, discoveredRelationships, err := invokeParser(ctx, resolver, location, lgr, parser, &env)
		if err != nil {
			// parsers may return errors and valid packages / relationships
			errs = unknown.Append(errs, location, err)
		}

		for _, p := range discoveredPackages {
			p.FoundBy = c.upstreamCataloger
			packages = append(packages, p)
		}

		relationships = append(relationships, discoveredRelationships...)
	}
	return c.process(ctx, resolver, packages, relationships, errs)
}

func (c *Cataloger) process(ctx context.Context, resolver file.Resolver, pkgs []pkg.Package, rels []artifact.Relationship, err error) ([]pkg.Package, []artifact.Relationship, error) {
	for _, p := range c.processors {
		pkgs, rels, err = p.process(ctx, resolver, pkgs, rels, err)
	}
	return pkgs, rels, err
}

func invokeParser(ctx context.Context, resolver file.Resolver, location file.Location, logger logger.Logger, parser Parser, env *Environment) ([]pkg.Package, []artifact.Relationship, error) {
	contentReader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		logger.WithFields("location", location.RealPath, "error", err).Warn("unable to fetch contents")
		return nil, nil, err
	}
	defer internal.CloseAndLogError(contentReader, location.AccessPath)

	discoveredPackages, discoveredRelationships, err := parser(ctx, resolver, env, file.NewLocationReadCloser(location, contentReader))
	if err != nil {
		// these errors are propagated up, and are likely to be coordinate errors
		logger.WithFields("location", location.RealPath, "error", err).Trace("cataloger returned errors")
	}

	return discoveredPackages, discoveredRelationships, err
}

// selectFiles takes a set of file trees and resolves and file references of interest for future cataloging
func (c *Cataloger) selectFiles(resolver file.Resolver) []request {
	var requests []request
	for _, proc := range c.requesters {
		requests = append(requests, proc(resolver, Environment{})...)
	}
	return requests
}
