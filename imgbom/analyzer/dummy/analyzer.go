package dummy

import (
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/tree"
)

// TODO: delete me

type Analyzer struct{}

func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

func (a *Analyzer) SelectFiles(trees []*tree.FileTree) []file.Reference {
	return []file.Reference{*trees[0].File("/etc/centos-release")}
}

func (a *Analyzer) Analyze(contents map[file.Reference]string) ([]pkg.Package, error) {
	return []pkg.Package{
		{
			Name:     "dummy",
			Version:  "1.0.0",
			Type:     pkg.DebPkg,
			Metadata: pkg.DummyPackage{Extra: "some extra metadata"},
		},
	}, nil
}
