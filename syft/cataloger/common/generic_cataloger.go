/*
Package common provides generic utilities used by multiple catalogers.
*/
package common

import (
	"strings"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

// GenericCataloger implements the Catalog interface and is responsible for dispatching the proper parser function for
// a given path or glob pattern. This is intended to be reusable across many package cataloger types.
type GenericCataloger struct {
	globParsers     map[string]ParserFn
	pathParsers     map[string]ParserFn
	selectedFiles   []file.Reference
	parsers         map[file.Reference]ParserFn
	upstreamMatcher string
}

// NewGenericCataloger if provided path-to-parser-function and glob-to-parser-function lookups creates a GenericCataloger
func NewGenericCataloger(pathParsers map[string]ParserFn, globParsers map[string]ParserFn, upstreamMatcher string) *GenericCataloger {
	return &GenericCataloger{
		globParsers:     globParsers,
		pathParsers:     pathParsers,
		selectedFiles:   make([]file.Reference, 0),
		parsers:         make(map[file.Reference]ParserFn),
		upstreamMatcher: upstreamMatcher,
	}
}

// Name returns a string that uniquely describes the upstream cataloger that this Generic Cataloger represents.
func (a *GenericCataloger) Name() string {
	return a.upstreamMatcher
}

// register pairs a set of file references with a parser function for future cataloging (when the file contents are resolved)
func (a *GenericCataloger) register(files []file.Reference, parser ParserFn) {
	a.selectedFiles = append(a.selectedFiles, files...)
	for _, f := range files {
		a.parsers[f] = parser
	}
}

// clear deletes all registered file-reference-to-parser-function pairings from former SelectFiles() and register() calls
func (a *GenericCataloger) clear() {
	a.selectedFiles = make([]file.Reference, 0)
	a.parsers = make(map[file.Reference]ParserFn)
}

// SelectFiles takes a set of file trees and resolves and file references of interest for future cataloging
func (a *GenericCataloger) SelectFiles(resolver scope.FileResolver) []file.Reference {
	// select by exact path
	for path, parser := range a.pathParsers {
		files, err := resolver.FilesByPath(file.Path(path))
		if err != nil {
			log.Errorf("cataloger failed to select files by path: %+v", err)
		}
		if files != nil {
			a.register(files, parser)
		}
	}

	// select by glob pattern
	for globPattern, parser := range a.globParsers {
		fileMatches, err := resolver.FilesByGlob(globPattern)
		if err != nil {
			log.Errorf("failed to find files by glob: %s", globPattern)
		}
		if fileMatches != nil {
			a.register(fileMatches, parser)
		}
	}

	return a.selectedFiles
}

// Catalog takes a set of file contents and uses any configured parser functions to resolve and return discovered packages
func (a *GenericCataloger) Catalog(contents map[file.Reference]string) ([]pkg.Package, error) {
	defer a.clear()

	packages := make([]pkg.Package, 0)

	for reference, parser := range a.parsers {
		content, ok := contents[reference]
		if !ok {
			log.Errorf("cataloger '%s' missing file content: %+v", a.upstreamMatcher, reference)
			continue
		}

		entries, err := parser(string(reference.Path), strings.NewReader(content))
		if err != nil {
			// TODO: should we fail? or only log?
			log.Errorf("cataloger '%s' failed to parse entries (reference=%+v): %+v", a.upstreamMatcher, reference, err)
			continue
		}

		for _, entry := range entries {
			entry.FoundBy = a.upstreamMatcher
			entry.Source = []file.Reference{reference}

			packages = append(packages, entry)
		}
	}

	return packages, nil
}
