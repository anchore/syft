package bus

import (
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/clio"
	"github.com/anchore/syft/internal/redact"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/event/monitor"
)

func Exit() {
	Publish(clio.ExitEvent(false))
}

func ExitWithInterrupt() {
	Publish(clio.ExitEvent(true))
}

func Report(report string) {
	if len(report) == 0 {
		return
	}
	report = redact.Apply(report)
	Publish(partybus.Event{
		Type:  event.CLIReport,
		Value: report,
	})
}

func Notify(message string) {
	Publish(partybus.Event{
		Type:  event.CLINotification,
		Value: message,
	})
}

func StartCatalogerTask(info monitor.GenericTask, size int64, initialStage string) *monitor.CatalogerTaskProgress {
	t := &monitor.CatalogerTaskProgress{
		AtomicStage: progress.NewAtomicStage(initialStage),
		Manual:      progress.NewManual(size),
	}

	Publish(partybus.Event{
		Type:   event.CatalogerTaskStarted,
		Source: info,
		Value:  progress.StagedProgressable(t),
	})

	return t
}
