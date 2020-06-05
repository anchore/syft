package analyzer

import (
	"github.com/anchore/imgbom/imgbom/analyzer/bundler"
	"github.com/anchore/imgbom/imgbom/analyzer/dpkg"
	"github.com/anchore/imgbom/imgbom/analyzer/python"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/imgbom/scope"
	"github.com/anchore/imgbom/internal/log"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/hashicorp/go-multierror"
)

var controllerInstance controller

func init() {
	controllerInstance = newController()
}

func Analyze(s scope.Scope) (*pkg.Catalog, error) {
	return controllerInstance.analyze(s)
}

type controller struct {
	analyzers []Analyzer
}

func newController() controller {
	ctrlr := controller{
		analyzers: make([]Analyzer, 0),
	}
	ctrlr.add(dpkg.NewAnalyzer())
	ctrlr.add(bundler.NewAnalyzer())
	ctrlr.add(python.NewAnalyzer())
	return ctrlr
}

func (c *controller) add(a Analyzer) {
	log.Debugf("adding analyzer: %s", a.Name())
	c.analyzers = append(c.analyzers, a)
}

func (c *controller) analyze(s scope.Scope) (*pkg.Catalog, error) {
	catalog := pkg.NewCatalog()
	fileSelection := make([]file.Reference, 0)

	// ask analyzers for files to extract from the image tar
	for _, a := range c.analyzers {
		fileSelection = append(fileSelection, a.SelectFiles(s.Trees)...)
		log.Debugf("analyzer '%s' selected '%d' files", a.Name(), len(fileSelection))
	}

	// fetch contents for requested selection by analyzers
	contents, err := s.Image.MultipleFileContentsByRef(fileSelection...)
	if err != nil {
		return nil, err
	}

	// perform analysis, accumulating errors for each failed analysis
	var errs error
	for _, a := range c.analyzers {
		// TODO: check for multiple rounds of analyses by Iterate error
		packages, err := a.Analyze(contents)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}

		log.Debugf("analyzer '%s' discovered '%d' packages", a.Name(), len(packages))

		for _, p := range packages {
			catalog.Add(p)
		}
	}

	if errs != nil {
		return nil, errs
	}

	return catalog, nil
}
