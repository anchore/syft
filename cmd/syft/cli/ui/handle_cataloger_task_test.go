package ui

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/bubbly/bubbles/taskprogress"
	syftEvent "github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/event/monitor"
)

func TestHandler_handleCatalogerTaskStarted(t *testing.T) {
	tests := []struct {
		name       string
		eventFn    func(*testing.T) partybus.Event
		iterations int
	}{
		{
			name: "cataloging task in progress",
			eventFn: func(t *testing.T) partybus.Event {
				src := &monitor.CatalogerTask{
					SubStatus:          false,
					RemoveOnCompletion: false,
					Title:              "some task title",
					TitleOnCompletion:  "some task done",
				}

				src.SetValue("some value")

				return partybus.Event{
					Type:   syftEvent.CatalogerTaskStarted,
					Source: src,
				}
			},
		},
		{
			name: "cataloging sub task in progress",
			eventFn: func(t *testing.T) partybus.Event {
				src := &monitor.CatalogerTask{
					SubStatus:          true,
					RemoveOnCompletion: false,
					Title:              "some task title",
					TitleOnCompletion:  "some task done",
				}

				src.SetValue("some value")

				return partybus.Event{
					Type:   syftEvent.CatalogerTaskStarted,
					Source: src,
				}
			},
		},
		{
			name: "cataloging sub task complete",
			eventFn: func(t *testing.T) partybus.Event {
				src := &monitor.CatalogerTask{
					SubStatus:          true,
					RemoveOnCompletion: false,
					Title:              "some task title",
					TitleOnCompletion:  "some task done",
				}

				src.SetValue("some value")
				src.SetCompleted()

				return partybus.Event{
					Type:   syftEvent.CatalogerTaskStarted,
					Source: src,
				}
			},
		},
		{
			name: "cataloging sub task complete with removal",
			eventFn: func(t *testing.T) partybus.Event {
				src := &monitor.CatalogerTask{
					SubStatus:          true,
					RemoveOnCompletion: true,
					Title:              "some task title",
					TitleOnCompletion:  "some task done",
				}

				src.SetValue("some value")
				src.SetCompleted()

				return partybus.Event{
					Type:   syftEvent.CatalogerTaskStarted,
					Source: src,
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
