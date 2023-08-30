package ui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/bubbly/bubbles/taskprogress"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event/monitor"
	syftEventParsers "github.com/anchore/syft/syft/event/parsers"
)

var _ progress.Stager = (*catalogerTaskStageAdapter)(nil)

type catalogerTaskStageAdapter struct {
	mon *monitor.CatalogerTask
}

func newCatalogerTaskStageAdapter(mon *monitor.CatalogerTask) *catalogerTaskStageAdapter {
	return &catalogerTaskStageAdapter{
		mon: mon,
	}
}

func (c catalogerTaskStageAdapter) Stage() string {
	return c.mon.GetValue()
}

func (m *Handler) handleCatalogerTaskStarted(e partybus.Event) []tea.Model {
	mon, err := syftEventParsers.ParseCatalogerTaskStarted(e)
	if err != nil {
		log.WithFields("error", err).Warn("unable to parse event")
		return nil
	}

	var prefix string
	if mon.SubStatus {
		// TODO: support list of sub-statuses, not just a single leaf
		prefix = "└── "
	}

	tsk := m.newTaskProgress(
		taskprogress.Title{
			// TODO: prefix should not be part of the title, but instead a separate field that is aware of the tree structure
			Default: prefix + mon.Title,
			Running: prefix + mon.Title,
			Success: prefix + mon.TitleOnCompletion,
		},
		taskprogress.WithStagedProgressable(
			struct {
				progress.Stager
				progress.Progressable
			}{
				Progressable: mon.GetMonitor(),
				Stager:       newCatalogerTaskStageAdapter(mon),
			},
		),
	)

	// TODO: this isn't ideal since the model stays around after it is no longer needed, but it works for now
	tsk.HideOnSuccess = mon.RemoveOnCompletion
	tsk.HideStageOnSuccess = false
	tsk.HideProgressOnSuccess = false

	tsk.TitleStyle = lipgloss.NewStyle()
	// TODO: this is a hack to get the spinner to not show up, but ideally the component would support making the spinner optional
	tsk.Spinner.Spinner.Frames = []string{" "}

	return []tea.Model{tsk}
}
