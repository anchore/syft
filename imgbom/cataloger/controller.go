package cataloger

import (
	"github.com/anchore/imgbom/imgbom/cataloger/bundler"
	"github.com/anchore/imgbom/imgbom/cataloger/dpkg"
	"github.com/anchore/imgbom/imgbom/cataloger/python"
	"github.com/anchore/imgbom/imgbom/cataloger/rpmdb"
	"github.com/anchore/imgbom/imgbom/event"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/imgbom/scope"
	"github.com/anchore/imgbom/internal/bus"
	"github.com/anchore/imgbom/internal/log"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/hashicorp/go-multierror"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
)

var controllerInstance controller

func init() {
	controllerInstance = newController()
}

func Catalogers() []string {
	c := make([]string, len(controllerInstance.catalogers))
	for idx, catalog := range controllerInstance.catalogers {
		c[idx] = catalog.Name()
	}
	return c
}

func Catalog(s scope.FileContentResolver) (*pkg.Catalog, error) {
	return controllerInstance.catalog(s)
}

type controller struct {
	catalogers []Cataloger
}

func newController() controller {
	ctrlr := controller{
		catalogers: make([]Cataloger, 0),
	}
	ctrlr.add(dpkg.NewCataloger())
	ctrlr.add(bundler.NewCataloger())
	ctrlr.add(python.NewCataloger())
	ctrlr.add(rpmdb.NewCataloger())
	return ctrlr
}

func (c *controller) add(a Cataloger) {
	log.Debugf("adding cataloger: %s", a.Name())
	c.catalogers = append(c.catalogers, a)
}

type Monitor struct {
	FilesProcessed     progress.Monitorable
	PackagesDiscovered progress.Monitorable
}

func (c *controller) trackCataloger() (*progress.Manual, *progress.Manual) {
	filesProcessed := progress.Manual{}
	packagesDiscovered := progress.Manual{}

	bus.Publish(partybus.Event{
		Type: event.CatalogerStarted,
		Value: Monitor{
			FilesProcessed:     progress.Monitorable(&filesProcessed),
			PackagesDiscovered: progress.Monitorable(&packagesDiscovered),
		},
	})
	return &filesProcessed, &packagesDiscovered
}

func (c *controller) catalog(s scope.FileContentResolver) (*pkg.Catalog, error) {
	catalog := pkg.NewCatalog()
	fileSelection := make([]file.Reference, 0)

	filesProcessed, packagesDiscovered := c.trackCataloger()

	// ask catalogers for files to extract from the image tar
	for _, a := range c.catalogers {
		fileSelection = append(fileSelection, a.SelectFiles(s)...)
		log.Debugf("cataloger '%s' selected '%d' files", a.Name(), len(fileSelection))
		filesProcessed.N += int64(len(fileSelection))
	}

	// fetch contents for requested selection by catalogers
	contents, err := s.MultipleFileContentsByRef(fileSelection...)
	if err != nil {
		return nil, err
	}

	// perform analysis, accumulating errors for each failed analysis
	var errs error
	for _, a := range c.catalogers {
		// TODO: check for multiple rounds of analyses by Iterate error
		packages, err := a.Catalog(contents)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}

		log.Debugf("cataloger '%s' discovered '%d' packages", a.Name(), len(packages))
		packagesDiscovered.N += int64(len(packages))

		for _, p := range packages {
			catalog.Add(p)
		}
	}

	if errs != nil {
		return nil, errs
	}

	filesProcessed.SetCompleted()
	packagesDiscovered.SetCompleted()

	return catalog, nil
}
