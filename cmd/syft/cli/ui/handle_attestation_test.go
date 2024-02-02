package ui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/bubbly/bubbles/taskprogress"
	syftEvent "github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/event/monitor"
)

func TestHandler_handleAttestationStarted(t *testing.T) {

	tests := []struct {
		name       string
		eventFn    func(*testing.T) partybus.Event
		iterations int
	}{
		{
			name: "attesting in progress",
			// note: this model depends on a background reader. Multiple iterations ensures that the
			// reader has time to at least start and process the test fixture before the runModel
			// test harness completes (which is a fake event loop anyway).
			iterations: 1,
			eventFn: func(t *testing.T) partybus.Event {
				reader := strings.NewReader("contents\nof\nstuff!")

				src := monitor.GenericTask{
					Title: monitor.Title{
						Default:      "Create a thing",
						WhileRunning: "Creating a thing",
						OnSuccess:    "Created a thing",
					},
					Context: "running a thing",
				}

				mon := progress.NewManual(-1)
				mon.Set(50)

				value := &monitor.ShellProgress{
					Reader:       reader,
					Progressable: mon,
				}

				return partybus.Event{
					Type:   syftEvent.AttestationStarted,
					Source: src,
					Value:  value,
				}
			},
		},
		{
			name: "attesting complete",
			// note: this model depends on a background reader. Multiple iterations ensures that the
			// reader has time to at least start and process the test fixture before the runModel
			// test harness completes (which is a fake event loop anyway).
			iterations: 1,
			eventFn: func(t *testing.T) partybus.Event {
				reader := strings.NewReader("contents\nof\nstuff!")

				src := monitor.GenericTask{
					Title: monitor.Title{
						Default:      "Create a thing",
						WhileRunning: "Creating a thing",
						OnSuccess:    "Created a thing",
					},
					Context: "running a thing",
				}

				mon := progress.NewManual(-1)
				mon.Set(50)
				mon.SetCompleted()

				value := &monitor.ShellProgress{
					Reader:       reader,
					Progressable: mon,
				}

				return partybus.Event{
					Type:   syftEvent.AttestationStarted,
					Source: src,
					Value:  value,
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

			models, _ := handler.Handle(event)
			require.Len(t, models, 2)

			t.Run("task line", func(t *testing.T) {
				tsk, ok := models[0].(taskprogress.Model)
				require.True(t, ok)

				gotModel := runModel(t, tsk, tt.iterations, taskprogress.TickMsg{
					Time:     time.Now(),
					Sequence: tsk.Sequence(),
					ID:       tsk.ID(),
				})

				got := gotModel.View()

				t.Log(got)
				snaps.MatchSnapshot(t, got)
			})

			t.Run("log", func(t *testing.T) {
				log, ok := models[1].(attestLogFrame)
				require.True(t, ok)

				gotModel := runModel(t, log, tt.iterations, attestLogFrameTickMsg{
					Time:     time.Now(),
					Sequence: log.sequence,
					ID:       log.id,
				}, log.reader.running)

				got := gotModel.View()

				t.Log(got)
				snaps.MatchSnapshot(t, got)
			})

		})
	}
}
