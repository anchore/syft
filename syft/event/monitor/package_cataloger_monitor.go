package monitor

import (
	"github.com/wagoodman/go-progress"
)

// PackageCatalogerMonitor provides progress-related data for observing the progress of a Catalog() call (published on the event bus).
type PackageCatalogerMonitor struct {
	FilesProcessed     progress.Monitorable // the number of files selected and contents analyzed from all registered catalogers
	PackagesDiscovered progress.Monitorable // the number of packages discovered from all registered catalogers
}
