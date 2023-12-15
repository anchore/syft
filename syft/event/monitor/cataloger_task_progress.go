package monitor

import (
	"github.com/wagoodman/go-progress"
)

const (
	TopLevelCatalogingTaskID = "cataloging"
	PackageCatalogingTaskID  = "package-cataloging"
)

type CatalogerTaskProgress struct {
	*progress.AtomicStage
	*progress.Manual
}
