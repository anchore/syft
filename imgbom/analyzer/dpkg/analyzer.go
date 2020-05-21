package dpkg

import (
	"strings"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/internal/log"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/tree"
)

type Analyzer struct {
	selectedFiles []file.Reference
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

func (a *Analyzer) Name() string {
	return "dpkg-analyzer"
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
			// TODO: test case
			log.WithFields(map[string]interface{}{
				"path":     reference.Path,
				"id":       reference.ID(),
				"analyzer": a.Name(),
			}).Errorf("analyzer file content missing")

			continue
		}

		entries, err := ParseEntries(strings.NewReader(content))
		if err != nil {
			// TODO: test case
			log.WithFields(map[string]interface{}{
				"path":     reference.Path,
				"id":       reference.ID(),
				"analyzer": a.Name(),
			}).Errorf("analyzer failed to parse entries: %w", err)

			continue
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
