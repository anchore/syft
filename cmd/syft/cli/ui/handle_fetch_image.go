package ui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/bubbly/bubbles/taskprogress"
	stereoEventParsers "github.com/anchore/stereoscope/pkg/event/parsers"
	"github.com/anchore/syft/internal/log"
)

func (m *Handler) handleFetchImage(e partybus.Event) []tea.Model {
	imgName, prog, err := stereoEventParsers.ParseFetchImage(e)
	if err != nil {
		log.WithFields("error", err).Warn("unable to parse event")
		return nil
	}

	tsk := m.newTaskProgress(
		taskprogress.Title{
			Default: "Load image",
			Running: "Loading image",
			Success: "Loaded image",
		},
		taskprogress.WithStagedProgressable(prog),
	)
	if imgName != "" {
		tsk.Context = []string{imgName}
	}

	return []tea.Model{tsk}
}
