package ui

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/bubbly/bubbles/taskprogress"
	syftEvent "github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/file/cataloger/secrets"
)

func TestHandler_handleSecretsCatalogerStarted(t *testing.T) {

	tests := []struct {
		name       string
		eventFn    func(*testing.T) partybus.Event
		iterations int
	}{
		{
			name: "cataloging in progress",
			eventFn: func(t *testing.T) partybus.Event {
				stage := &progress.Stage{
					Current: "current",
				}
				secretsDiscovered := progress.NewManual(-1)
				secretsDiscovered.Set(64)
				prog := progress.NewManual(72)
				prog.Set(50)

				return partybus.Event{
					Type:   syftEvent.SecretsCatalogerStarted,
					Source: secretsDiscovered,
					Value: secrets.Monitor{
						Stager:            progress.Stager(stage),
						SecretsDiscovered: secretsDiscovered,
						Progressable:      prog,
					},
				}
			},
		},
		{
			name: "cataloging complete",
			eventFn: func(t *testing.T) partybus.Event {
				stage := &progress.Stage{
					Current: "current",
				}
				secretsDiscovered := progress.NewManual(-1)
				secretsDiscovered.Set(64)
				prog := progress.NewManual(72)
				prog.Set(72)
				prog.SetCompleted()

				return partybus.Event{
					Type:   syftEvent.SecretsCatalogerStarted,
					Source: secretsDiscovered,
					Value: secrets.Monitor{
						Stager:            progress.Stager(stage),
						SecretsDiscovered: secretsDiscovered,
						Progressable:      prog,
					},
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := tt.eventFn(t)
			handler := New(DefaultHandlerConfig())
			handler.WindowSize = tea.WindowSizeMsg{
				Width:  100,
				Height: 80,
			}

			models := handler.Handle(event)
			require.Len(t, models, 1)
			model := models[0]

			tsk, ok := model.(taskprogress.Model)
			require.True(t, ok)

			got := runModel(t, tsk, tt.iterations, taskprogress.TickMsg{
				Time:     time.Now(),
				Sequence: tsk.Sequence(),
				ID:       tsk.ID(),
			})
			t.Log(got)
			snaps.MatchSnapshot(t, got)
		})
	}
}
