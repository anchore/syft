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
	"github.com/anchore/syft/syft/pkg/cataloger"
)

func TestHandler_handlePackageCatalogerStarted(t *testing.T) {

	tests := []struct {
		name       string
		eventFn    func(*testing.T) partybus.Event
		iterations int
	}{
		{
			name: "cataloging in progress",
			eventFn: func(t *testing.T) partybus.Event {
				prog := &progress.Manual{}
				prog.SetTotal(100)
				prog.Set(50)

				mon := cataloger.Monitor{
					FilesProcessed:     progress.NewManual(-1),
					PackagesDiscovered: prog,
				}

				return partybus.Event{
					Type:  syftEvent.PackageCatalogerStarted,
					Value: mon,
				}
			},
		},
		{
			name: "cataloging only files complete",
			eventFn: func(t *testing.T) partybus.Event {
				prog := &progress.Manual{}
				prog.SetTotal(100)
				prog.Set(50)

				files := progress.NewManual(-1)
				files.SetCompleted()

				mon := cataloger.Monitor{
					FilesProcessed:     files,
					PackagesDiscovered: prog,
				}

				return partybus.Event{
					Type:  syftEvent.PackageCatalogerStarted,
					Value: mon,
				}
			},
		},
		{
			name: "cataloging only packages complete",
			eventFn: func(t *testing.T) partybus.Event {
				prog := &progress.Manual{}
				prog.SetTotal(100)
				prog.Set(100)
				prog.SetCompleted()

				files := progress.NewManual(-1)

				mon := cataloger.Monitor{
					FilesProcessed:     files,
					PackagesDiscovered: prog,
				}

				return partybus.Event{
					Type:  syftEvent.PackageCatalogerStarted,
					Value: mon,
				}
			},
		},
		{
			name: "cataloging complete",
			eventFn: func(t *testing.T) partybus.Event {
				prog := &progress.Manual{}
				prog.SetTotal(100)
				prog.Set(100)
				prog.SetCompleted()

				files := progress.NewManual(-1)
				files.SetCompleted()

				mon := cataloger.Monitor{
					FilesProcessed:     files,
					PackagesDiscovered: prog,
				}

				return partybus.Event{
					Type:  syftEvent.PackageCatalogerStarted,
					Value: mon,
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
