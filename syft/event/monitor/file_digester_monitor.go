package monitor

import (
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/syft/event"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
)

func FileDigesterMonitor(locations int64) (*progress.Stage, *progress.Manual) {
	stage := &progress.Stage{}
	prog := &progress.Manual{
		Total: locations,
	}

	bus.Publish(partybus.Event{
		Type: event.FileDigestsCatalogerStarted,
		Value: struct {
			progress.Stager
			progress.Progressable
		}{
			Stager:       progress.Stager(stage),
			Progressable: prog,
		},
	})

	return stage, prog
}
