package common

import (
	"strings"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/internal/log"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/tree"
)

// TODO: put under test...

type GenericAnalyzer struct {
	globParserDispatch map[string]ParserFn
	pathParserDispatch map[string]ParserFn
	selectedFiles      []file.Reference
	parsers            map[file.Reference]ParserFn
}

func NewGenericAnalyzer(pathParserDispatch map[string]ParserFn, globParserDispatch map[string]ParserFn) GenericAnalyzer {
	return GenericAnalyzer{
		globParserDispatch: globParserDispatch,
		pathParserDispatch: pathParserDispatch,
		selectedFiles:      make([]file.Reference, 0),
		parsers:            make(map[file.Reference]ParserFn),
	}
}

func (a *GenericAnalyzer) register(files []file.Reference, parser ParserFn) {
	a.selectedFiles = append(a.selectedFiles, files...)
	for _, f := range files {
		a.parsers[f] = parser
	}
}

func (a *GenericAnalyzer) clear() {
	a.selectedFiles = make([]file.Reference, 0)
	a.parsers = make(map[file.Reference]ParserFn)
}

func (a *GenericAnalyzer) SelectFiles(trees []tree.FileTreeReader) []file.Reference {
	for _, tree := range trees {
		// select by exact path
		for path, parser := range a.globParserDispatch {
			f := tree.File(file.Path(path))
			if f != nil {
				a.register([]file.Reference{*f}, parser)
			}
		}

		// select by pattern
		for globPattern, parser := range a.globParserDispatch {
			fileMatches, err := tree.FilesByGlob(globPattern)
			if err != nil {
				log.Errorf("failed to find files by glob: %s", globPattern)
			}
			if fileMatches != nil {
				a.register(fileMatches, parser)
			}
		}
	}

	return a.selectedFiles
}

func (a *GenericAnalyzer) Analyze(contents map[file.Reference]string, upstreamMatcher string) ([]pkg.Package, error) {
	defer a.clear()

	packages := make([]pkg.Package, 0)

	for reference, parser := range a.parsers {
		content, ok := contents[reference]
		if !ok {
			log.Errorf("analyzer '%s' missing file content: %+v", upstreamMatcher, reference)
			continue
		}

		entries, err := parser(strings.NewReader(content))
		if err != nil {
			log.Errorf("analyzer '%s' failed to parse entries (reference=%+v): %w", upstreamMatcher, reference, err)
			continue
		}

		for _, entry := range entries {
			entry.FoundBy = upstreamMatcher
			entry.Source = []file.Reference{reference}

			packages = append(packages, entry)
		}
	}

	return packages, nil
}
