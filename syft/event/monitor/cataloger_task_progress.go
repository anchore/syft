package monitor

import (
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/syft/event"
)

type CatalogerTask struct {
	*progress.AtomicStage
	*progress.Manual
}

func StartCatalogerTask(info GenericTask, size int64, initialStage string) *CatalogerTask {
	t := &CatalogerTask{
		AtomicStage: progress.NewAtomicStage(initialStage),
		Manual:      progress.NewManual(size),
	}

	bus.Publish(partybus.Event{
		Type:   event.CatalogerTaskStarted,
		Source: info,
		Value:  progress.StagedProgressable(t),
	})

	return t
}
