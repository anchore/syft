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

// Cataloger implements the Catalog interface and is responsible for dispatching the proper parser function for
// a given path or glob pattern. This is intended to be reusable across many package cataloger types.
type Cataloger struct {
	upstreamCataloger string
	mimeTypePatterns  []string
	globRegExp        []*regexp.Regexp
	paths             []string
	parser            map[string]Parser
}

func globToRegexPattern(glob string) string {
	// rDir -> "(.*/)*"
	// A placeholder value to allow replacement of other * in the glob with different meaning
	const rDir = "R-DIR"
	rPattern := strings.ReplaceAll(glob, "**/", rDir)
	rPattern = strings.ReplaceAll(rPattern, "*", ".*")
	rPattern = strings.ReplaceAll(rPattern, "{", "(")
	rPattern = strings.ReplaceAll(rPattern, "}", ")")
	rPattern = strings.ReplaceAll(rPattern, ",", "|")
	rPattern = strings.ReplaceAll(rPattern, rDir, "(.*/)*")
	rPattern += "$"
	return rPattern
}

func (c *Cataloger) WithParserByGlobs(parser Parser, globs ...string) *Cataloger {
	for _, glob := range globs {
		regexPattern := globToRegexPattern(glob)
		c.parser[regexPattern] = parser
		regex, _ := regexp.Compile(regexPattern)
		c.globRegExp = append(c.globRegExp, regex)
	}

	return c
}

func (c *Cataloger) WithParserByMimeTypes(parser Parser, types ...string) *Cataloger {
	for _, mimeType := range types {
		c.parser[mimeType] = parser
		c.mimeTypePatterns = append(c.mimeTypePatterns, mimeType)
	}
	return c
}

func (c *Cataloger) WithParserByPath(parser Parser, paths ...string) *Cataloger {
	for _, path := range paths {
		c.parser[path] = parser
		c.paths = append(c.paths, path)
	}

	return c
}

// NewCataloger if provided path-to-parser-function and glob-to-parser-function lookups creates a Cataloger
func NewCataloger(upstreamCataloger string) *Cataloger {
	return &Cataloger{
		upstreamCataloger: upstreamCataloger,
		parser:            map[string]Parser{},
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

	for location := range resolver.AllLocations() {
		discoveredPackages, discoveredRelationships, err := c.parseRequest(resolver, location, env)

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

func (c *Cataloger) parseRequest(resolver source.FileResolver, location source.Location, env Environment) ([]pkg.Package, []artifact.Relationship, error) {
	var parser Parser

	// check if the `location` is read by the cataloger.

	isRegexMatch, isMimeTypeMatch, isPathMatch := false, false, false

	// check glob match first
	for _, regex := range c.globRegExp {
		regexMatch := location.MatchesRePattern(regex)
		isRegexMatch = regexMatch
		if isRegexMatch {
			parser = c.parser[regex.String()]
			break
		}
	}

	// check for mime type match
	for _, mimeType := range c.mimeTypePatterns {
		if isRegexMatch || isMimeTypeMatch {
			break
		}
		isMimeTypeMatch = resolver.HasMimeTypeAtLocation(mimeType, location)
		if isMimeTypeMatch {
			parser = c.parser[mimeType]
			break
		}
	}

	// check for path match
	for _, expectedPath := range c.paths {
		if isRegexMatch || isMimeTypeMatch || isPathMatch {
			break
		}

		isPathMatch = resolver.HasPath(expectedPath)
		if isPathMatch {
			parser = c.parser[expectedPath]
			break
		}
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
