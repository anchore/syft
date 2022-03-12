package monitor

import (
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/syft/event"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
)

type SecretsCatalogerMonitor struct {
	progress.Stager
	SecretsDiscovered progress.Monitorable
	progress.Progressable
}

func NewSecretsCatalogerMonitor(locations int64) (*progress.Stage, *progress.Manual, *progress.Manual) {
	stage := &progress.Stage{}
	secretsDiscovered := &progress.Manual{}
	prog := &progress.Manual{
		Total: locations,
	}

	bus.Publish(partybus.Event{
		Type:   event.SecretsCatalogerStarted,
		Source: secretsDiscovered,
		Value: SecretsCatalogerMonitor{
			Stager:            progress.Stager(stage),
			SecretsDiscovered: secretsDiscovered,
			Progressable:      prog,
		},
	})

	return stage, prog, secretsDiscovered
}
