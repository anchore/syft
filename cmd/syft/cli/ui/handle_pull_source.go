package ui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/bubbly/bubbles/taskprogress"
	"github.com/anchore/syft/internal/log"
	syftEventParsers "github.com/anchore/syft/syft/event/parsers"
)

func (m *Handler) handlePullSourceStarted(e partybus.Event) []tea.Model {
	prog, info, err := syftEventParsers.ParsePullSourceStarted(e)
	if err != nil {
		log.WithFields("error", err).Debug("unable to parse event")
		return nil
	}

	tsk := m.newTaskProgress(
		taskprogress.Title{
			Default: info.Title.Default,
			Running: info.Title.WhileRunning,
			Success: info.Title.OnSuccess,
		},
		taskprogress.WithStagedProgressable(prog),
	)

	tsk.HideOnSuccess = info.HideOnSuccess
	tsk.HideStageOnSuccess = info.HideStageOnSuccess
	tsk.HideProgressOnSuccess = true

	if info.Context != "" {
		tsk.Context = []string{info.Context}
	}

	return []tea.Model{tsk}
}
