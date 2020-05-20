package dpkg

import (
	"strings"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/tree"
)

type Analyzer struct {
	selectedFiles []file.Reference
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

func (a *Analyzer) SelectFiles(trees []*tree.FileTree) []file.Reference {
	files := make([]file.Reference, 0)
	for _, tree := range trees {
		// TODO: extract into function/slice/etc
		file := tree.File("/var/lib/dpkg/status")
		if file != nil {
			files = append(files, *file)
		}
	}

	a.selectedFiles = files

	return files
}

func (a *Analyzer) Analyze(contents map[file.Reference]string) ([]pkg.Package, error) {
	packages := make([]pkg.Package, 0)
	for _, reference := range a.selectedFiles {
		content, ok := contents[reference]
		if !ok {
			// TODO: this needs handling
			panic(reference)
		}

		entries, err := ParseEntries(strings.NewReader(content))
		if err != nil {
			// TODO: punt for now, we need to handle this
			panic(err)
		}
		for _, entry := range entries {
			packages = append(packages, pkg.Package{
				Name:     entry.Package,
				Version:  entry.Version,
				Type:     pkg.DebPkg,
				Source:   []file.Reference{reference},
				Metadata: entry,
			})
		}
	}
	return packages, nil
}
