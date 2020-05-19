package analyzer

import (
	"github.com/anchore/imgbom/imgbom/analyzer/dpkg"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/imgbom/scope"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/hashicorp/go-multierror"
)

var controllerInstance controller

func init() {
	controllerInstance = controller{
		analyzers: make([]Analyzer, 0),
	}
	controllerInstance.add(dpkg.NewAnalyzer())
}

func Analyze(s scope.Scope) (pkg.Catalog, error) {
	return controllerInstance.analyze(s)
}

type controller struct {
	analyzers []Analyzer
}

func (c *controller) add(a Analyzer) {
	c.analyzers = append(c.analyzers, a)
}

func (c *controller) analyze(s scope.Scope) (pkg.Catalog, error) {
	catalog := pkg.NewCatalog()
	fileSelection := make([]file.Reference, 0)

	// ask analyzers for files to extract from the image tar
	for _, a := range c.analyzers {
		fileSelection = append(fileSelection, a.SelectFiles(s.Trees)...)
	}

	// fetch contents for requested selection by analyzers
	contents, err := s.Image.MultipleFileContentsByRef(fileSelection...)
	if err != nil {
		return pkg.Catalog{}, err
	}

	// perform analysis, accumulating errors for each failed analysis
	var errs error
	for _, a := range c.analyzers {
		packages, err := a.Analyze(contents)
		// TODO: check for multiple rounds of analyses by Iterate error
		if err != nil {
			errs = multierror.Append(errs, err)
		}
		for _, p := range packages {
			catalog.Add(p)
		}
	}

	if errs != nil {
		return pkg.Catalog{}, errs
	}

	return catalog, nil
}
