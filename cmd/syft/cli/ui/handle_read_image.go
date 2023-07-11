package ui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/bubbly/bubbles/taskprogress"
	stereoEventParsers "github.com/anchore/stereoscope/pkg/event/parsers"
	"github.com/anchore/syft/internal/log"
)

func (m *Handler) handleReadImage(e partybus.Event) []tea.Model {
	imgMetadata, prog, err := stereoEventParsers.ParseReadImage(e)
	if err != nil {
		log.WithFields("error", err).Warn("unable to parse event")
		return nil
	}

	tsk := m.newTaskProgress(
		taskprogress.Title{
			Default: "Parse image",
			Running: "Parsing image",
			Success: "Parsed image",
		},
		taskprogress.WithProgress(prog),
	)

	if imgMetadata != nil {
		tsk.Context = []string{imgMetadata.ID}
	}

	return []tea.Model{tsk}
}
