package bundler

import (
	"io"
	"strings"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/internal/log"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/tree"
)

var parserDispatch = map[string]parserFn{
	"*/Gemfile.lock": ParseGemfileLockEntries,
}

type parserFn func(io.Reader) ([]pkg.Package, error)

type Analyzer struct {
	selectedFiles []file.Reference
	parsers       map[file.Reference]parserFn
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{
		selectedFiles: make([]file.Reference, 0),
		parsers:       make(map[file.Reference]parserFn),
	}
}

func (a *Analyzer) Name() string {
	return "bundler-analyzer"
}

func (a *Analyzer) register(files []file.Reference, parser parserFn) {
	a.selectedFiles = append(a.selectedFiles, files...)
	for _, f := range files {
		a.parsers[f] = parser
	}
}

func (a *Analyzer) clear() {
	a.selectedFiles = make([]file.Reference, 0)
	a.parsers = make(map[file.Reference]parserFn)
}

func (a *Analyzer) SelectFiles(trees []tree.FileTreeReader) []file.Reference {
	for _, tree := range trees {
		for globPattern, parser := range parserDispatch {
			fileMatches, err := tree.FilesByGlob(globPattern)
			if err != nil {
				log.Errorf("'%s' failed to find files by glob: %s", a.Name(), globPattern)
			}
			if fileMatches != nil {
				a.register(fileMatches, parser)
			}
		}
	}

	return a.selectedFiles
}

func (a *Analyzer) Analyze(contents map[file.Reference]string) ([]pkg.Package, error) {
	defer a.clear()

	packages := make([]pkg.Package, 0)

	for reference, parser := range a.parsers {
		content, ok := contents[reference]
		if !ok {
			log.Errorf("analyzer '%s' file content missing: %+v", a.Name(), reference)
			continue
		}

		entries, err := parser(strings.NewReader(content))
		if err != nil {
			log.Errorf("analyzer failed to parse entries (reference=%+v): %w", reference, err)
			continue
		}

		for _, entry := range entries {
			entry.FoundBy = a.Name()
			entry.Source = []file.Reference{reference}

			packages = append(packages, entry)
		}
	}

	return packages, nil
}
