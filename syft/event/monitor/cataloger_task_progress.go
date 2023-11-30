package monitor

import (
	"github.com/wagoodman/go-progress"
)

type CatalogerTaskProgress struct {
	*progress.AtomicStage
	*progress.Manual
}
