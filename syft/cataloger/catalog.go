package cataloger

import (
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
	"github.com/hashicorp/go-multierror"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
)

// Monitor provides progress-related data for observing the progress of a Catalog() call (published on the event bus).
type Monitor struct {
	FilesProcessed     progress.Monitorable // the number of files selected and contents analyzed from all registered catalogers
	PackagesDiscovered progress.Monitorable // the number of packages discovered from all registered catalogers
}

// newMonitor creates a new Monitor object and publishes the object on the bus as a CatalogerStarted event.
func newMonitor() (*progress.Manual, *progress.Manual) {
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

// Catalog a given scope (container image or filesystem) with the given catalogers, returning all discovered packages.
// In order to efficiently retrieve contents from a underlying container image the content fetch requests are
// done in bulk. Specifically, all files of interest are collected from each catalogers and accumulated into a single
// request.
func Catalog(resolver scope.Resolver, catalogers ...Cataloger) (*pkg.Catalog, error) {
	catalog := pkg.NewCatalog()
	filesProcessed, packagesDiscovered := newMonitor()

	// perform analysis, accumulating errors for each failed analysis
	var errs error
	for _, theCataloger := range catalogers {
		// TODO: check for multiple rounds of analyses by Iterate error
		packages, err := theCataloger.Catalog(resolver)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}

		log.Debugf("cataloger '%s' discovered '%d' packages", theCataloger.Name(), len(packages))
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
