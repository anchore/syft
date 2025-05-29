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
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/event/monitor"
)

func TestHandler_handlePullSourceStarted(t *testing.T) {

	tests := []struct {
		name       string
		eventFn    func(*testing.T) partybus.Event
		iterations int
	}{
		{
			name: "snap download in progress",
			eventFn: func(t *testing.T) partybus.Event {
				stage := progress.NewAtomicStage("")
				manual := progress.NewManual(0)
				manual.SetTotal(1000000) // 1MB file
				manual.Set(250000)       // 25% downloaded

				taskProg := &monitor.TaskProgress{
					AtomicStage: stage,
					Manual:      manual,
				}

				genericTask := monitor.GenericTask{
					Title: monitor.Title{
						Default:      "Downloading snap",
						WhileRunning: "Downloading snap file...",
						OnSuccess:    "Snap downloaded",
					},
					Context:            "example-app_1.0_amd64.snap",
					HideOnSuccess:      false,
					HideStageOnSuccess: true,
					ID:                 "snap-download-123",
				}

				return partybus.Event{
					Type:   event.PullSourceStarted,
					Source: genericTask,
					Value:  taskProg,
				}
			},
			iterations: 5,
		},
		{
			name: "snap download complete",
			eventFn: func(t *testing.T) partybus.Event {
				stage := progress.NewAtomicStage("")
				manual := progress.NewManual(0)
				manual.SetTotal(1000000) // 1MB file
				manual.Set(1000000)      // 100% downloaded
				manual.SetCompleted()

				taskProg := &monitor.TaskProgress{
					AtomicStage: stage,
					Manual:      manual,
				}

				genericTask := monitor.GenericTask{
					Title: monitor.Title{
						Default:      "Downloading snap",
						WhileRunning: "Downloading snap file...",
						OnSuccess:    "Snap downloaded successfully",
					},
					Context:            "example-app_1.0_amd64.snap",
					HideOnSuccess:      false,
					HideStageOnSuccess: true,
					ID:                 "snap-download-123",
				}

				return partybus.Event{
					Type:   event.PullSourceStarted,
					Source: genericTask,
					Value:  taskProg,
				}
			},
			iterations: 3,
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

			models := handler.handlePullSourceStarted(event)
			require.Len(t, models, 1)
			model := models[0]

			tsk, ok := model.(taskprogress.Model)
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
	}
}
