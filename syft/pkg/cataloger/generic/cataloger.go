package generic

import (
	"regexp"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

type processor func(resolver source.FileResolver, env Environment) []request

type request struct {
	source.Location
	Parser
}

// Cataloger implements the Catalog interface and is responsible for dispatching the proper parser function for
// a given path or glob pattern. This is intended to be reusable across many package cataloger types.
type Cataloger struct {
	processor         []processor
	upstreamCataloger string
	mimeTypePatterns  []string
	globRegExp        []*regexp.Regexp
	paths             []string
}

func (c *Cataloger) WithParserByGlobs(parser Parser, globs... string) *Cataloger {
	c.processor = append(c.processor,
		func(resolver source.FileResolver, env Environment) []request {
			var requests []request
			for _, g := range globs {
				// TODO: add more trace logging here
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

	// rDir -> "(.*/)*"
	// A placeholder value to allow replacement of other * in the glob with different meaning
	const rDir = "R-DIR"
	for _, glob := range globs {
		regexPattern := strings.ReplaceAll(glob, "**/", rDir)
		regexPattern = strings.ReplaceAll(regexPattern, "*", ".*")
		regexPattern = strings.ReplaceAll(regexPattern, "{", "(")
		regexPattern = strings.ReplaceAll(regexPattern, "}", ")")
		regexPattern = strings.ReplaceAll(regexPattern, ",", "|")
		regexPattern = strings.ReplaceAll(regexPattern, rDir, "(.*/)*")
		regex, _ := regexp.Compile(regexPattern)
		c.globRegExp = append(c.globRegExp, regex)
	}

	return c
}

func (c *Cataloger) WithParserByMimeTypes(parser Parser, types ...string) *Cataloger {
	c.processor = append(c.processor,
		func(resolver source.FileResolver, env Environment) []request {
			var requests []request
			for _, t := range types {
				// TODO: add more trace logging here
				matches, err := resolver.FilesByMIMEType(t)
				if err != nil {
					log.Warnf("unable to process mimetype=%q: %+v", t, err)
					continue
				}
				requests = append(requests, makeRequests(parser, matches)...)
			}
			return requests
		},
	)
	c.mimeTypePatterns = append(c.mimeTypePatterns, types...)
	return c
}

func (c *Cataloger) WithParserByPath(parser Parser, paths ...string) *Cataloger {
	c.processor = append(c.processor,
		func(resolver source.FileResolver, env Environment) []request {
			var requests []request
			for _, g := range paths {
				// TODO: add more trace logging here
				matches, err := resolver.FilesByPath(g)
				if err != nil {
					log.Warnf("unable to process path=%q: %+v", g, err)
					continue
				}
				requests = append(requests, makeRequests(parser, matches)...)
			}
			return requests
		},
	)
	c.paths = append(c.paths, paths...)
	return c
}

func makeRequests(parser Parser, locations []source.Location) []request {
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
func (c *Cataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package
	var relationships []artifact.Relationship

	env := Environment{
		// TODO: consider passing into the cataloger, this would affect the cataloger interface (and all implementations). This can be deferred until later.
		LinuxRelease: linux.IdentifyRelease(resolver),
	}

	for _, req := range c.selectFiles(resolver) {
		location, parser := req.Location, req.Parser

		discoveredPackages, discoveredRelationships, err := c.parseRequest(resolver, location, parser, env)

		if err != nil {
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
func (c *Cataloger) selectFiles(resolver source.FileResolver) []request {
	var requests []request
	for _, proc := range c.processor {
		requests = append(requests, proc(resolver, Environment{})...)
	}
	return requests
}

func (c *Cataloger) parseRequest(resolver source.FileResolver, location source.Location, parser Parser, env Environment) ([]pkg.Package, []artifact.Relationship, error) {
	// check if the `location` is read by the cataloger.

	isRegexMatch, isMimeTypeMatch, isPathMatch := false, false, false

	// check glob match first
	for _, regex := range c.globRegExp {
		if isRegexMatch {
			break
		}
		regexMatch := location.MatchesRePattern(regex)
		isRegexMatch = regexMatch
		// isRegexMatch = true
	}

	// check for mime type match
	for _, mimeType := range c.mimeTypePatterns {
		if isRegexMatch || isMimeTypeMatch {
			break
		}

		isMimeTypeMatch = resolver.HasMimeTypeAtLocation(mimeType, location)
	}

	// check for path match
	for _, expectedPath := range c.paths {
		if isRegexMatch || isMimeTypeMatch || isPathMatch {
			break
		}

		isPathMatch = resolver.HasPath(expectedPath)
	}

	if !(isRegexMatch || isMimeTypeMatch || isPathMatch) {
		// no matches - lets return
		return []pkg.Package{}, []artifact.Relationship{}, nil
	}

	logger := log.Nested("cataloger", c.upstreamCataloger)

	log.WithFields("path", location.RealPath).Trace("parsing file contents")

	contentReader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		logger.WithFields("location", location.RealPath, "error", err).Warn("unable to fetch contents")
		return nil, nil, err
	}

	discoveredPackages, discoveredRelationships, err := parser(resolver, &env, source.NewLocationReadCloser(location, contentReader))
	internal.CloseAndLogError(contentReader, location.VirtualPath)
	if err != nil {
		logger.WithFields("location", location.RealPath, "error", err).Warnf("cataloger failed")
		return nil, nil, err
	}

	return discoveredPackages, discoveredRelationships, nil

}
