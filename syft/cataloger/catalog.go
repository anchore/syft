package cataloger

import (
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
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

// Catalog a given source (container image or filesystem) with the given catalogers, returning all discovered packages.
// In order to efficiently retrieve contents from a underlying container image the content fetch requests are
// done in bulk. Specifically, all files of interest are collected from each catalogers and accumulated into a single
// request.
func Catalog(resolver source.Resolver, cpeDictionary cpe.Dictionary, theDistro *distro.Distro, catalogers ...Cataloger) (*pkg.Catalog, error) {
	catalog := pkg.NewCatalog()
	filesProcessed, packagesDiscovered := newMonitor()

	// perform analysis, accumulating errors for each failed analysis
	var errs error
	for _, theCataloger := range catalogers {
		// find packages from the underlying raw data
		packages, err := theCataloger.Catalog(resolver)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}

		catalogedPackages := len(packages)

		log.Debugf("cataloger '%s' discovered '%d' packages", theCataloger.Name(), catalogedPackages)
		packagesDiscovered.N += int64(catalogedPackages)

		for _, p := range packages {
			// generate CPEs
			p.CPEs = cpeDictionary.IdentifyPackageCPEs(p)

			// generate PURL
			p.PURL = generatePackageURL(p, theDistro)

			// add to catalog
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
