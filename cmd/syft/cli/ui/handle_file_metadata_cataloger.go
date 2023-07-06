package ui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/bubbly/bubbles/taskprogress"
	"github.com/anchore/syft/internal/log"
	syftEventParsers "github.com/anchore/syft/syft/event/parsers"
)

func (m *Handler) handleFileMetadataCatalogerStarted(e partybus.Event) []tea.Model {
	prog, err := syftEventParsers.ParseFileMetadataCatalogingStarted(e)
	if err != nil {
		log.WithFields("error", err).Warn("unable to parse event")
		return nil
	}

	tsk := m.newTaskProgress(
		taskprogress.Title{
			Default: "Catalog file metadata",
			Running: "Cataloging file metadata",
			Success: "Cataloged file metadata",
		},
		taskprogress.WithStagedProgressable(prog),
	)

	return []tea.Model{tsk}
}
