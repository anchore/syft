package monitor

import (
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/syft/event"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
)

// PackageCatalogerMonitor provides progress-related data for observing the progress of a Catalog() call (published on the event bus).
type PackageCatalogerMonitor struct {
	FilesProcessed     progress.Monitorable // the number of files selected and contents analyzed from all registered catalogers
	PackagesDiscovered progress.Monitorable // the number of packages discovered from all registered catalogers
}

// NewPackageCatalogerMonitor creates a new PackageCatalogerMonitor object and publishes the object on the bus as a PackageCatalogerStarted event.
func NewPackageCatalogerMonitor() (*progress.Manual, *progress.Manual) {
	filesProcessed := progress.Manual{}
	packagesDiscovered := progress.Manual{}

	bus.Publish(partybus.Event{
		Type: event.PackageCatalogerStarted,
		Value: PackageCatalogerMonitor{
			FilesProcessed:     progress.Monitorable(&filesProcessed),
			PackagesDiscovered: progress.Monitorable(&packagesDiscovered),
		},
	})
	return &filesProcessed, &packagesDiscovered
}
