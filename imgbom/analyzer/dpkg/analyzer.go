package dpkg

import (
	"github.com/anchore/imgbom/imgbom/analyzer/common"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/tree"
)

type Analyzer struct {
	analyzer common.GenericAnalyzer
}

func NewAnalyzer() *Analyzer {
	pathParserDispatch := map[string]common.ParserFn{
		"/var/lib/dpkg/status": parseDpkgStatus,
	}

	return &Analyzer{
		analyzer: common.NewGenericAnalyzer(pathParserDispatch, nil),
	}
}

func (a *Analyzer) Name() string {
	return "dpkg-analyzer"
}

func (a *Analyzer) SelectFiles(trees []tree.FileTreeReader) []file.Reference {
	return a.analyzer.SelectFiles(trees)
}

func (a *Analyzer) Analyze(contents map[file.Reference]string) ([]pkg.Package, error) {
	return a.analyzer.Analyze(contents, a.Name())
}
