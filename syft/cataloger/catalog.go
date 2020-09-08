package cataloger

import (
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
	"github.com/hashicorp/go-multierror"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
)

// Catalog a given scope (container image or filesystem) with the given catalogers, returning all discovered packages.
// In order to efficiently retrieve contents from a underlying container image the content fetch requests are
// done in bulk. Specifically, all files of interest are collected from each catalogers and accumulated into a single
// request.
func Catalog(resolver scope.Resolver, catalogers ...Cataloger) (*pkg.Catalog, error) {
	catalog := pkg.NewCatalog()
	fileSelection := make([]file.Reference, 0)

	filesProcessed, packagesDiscovered := newMonitor()

	// ask catalogers for files to extract from the image tar
	for _, a := range catalogers {
		catalogerSelection := a.SelectFiles(resolver)
		fileSelection = append(fileSelection, catalogerSelection...)
		log.Debugf("cataloger '%s' selected '%d' files", a.Name(), len(catalogerSelection))
		filesProcessed.N += int64(len(fileSelection))
	}

	// fetch contents for requested selection by catalogers
	// TODO: we should consider refactoring to return a set of io.Readers instead of the full contents themselves (allow for optional buffering).
	contents, err := resolver.MultipleFileContentsByRef(fileSelection...)
	if err != nil {
		return nil, err
	}

	// perform analysis, accumulating errors for each failed analysis
	var errs error
	for _, c := range catalogers {
		// TODO: check for multiple rounds of analyses by Iterate error
		packages, err := c.Catalog(contents)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}

		log.Debugf("cataloger '%s' discovered '%d' packages", c.Name(), len(packages))
		packagesDiscovered.N += int64(len(packages))

		catalogerName := c.Name()
		for _, p := range packages {
			p.FoundBy = catalogerName
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
