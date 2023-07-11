package ui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/bubbly/bubbles/taskprogress"
	"github.com/anchore/syft/internal/log"
	syftEventParsers "github.com/anchore/syft/syft/event/parsers"
	"github.com/anchore/syft/syft/file/cataloger/secrets"
)

var _ progress.StagedProgressable = (*secretsCatalogerProgressAdapter)(nil)

// Deprecated: will be removed in syft 1.0
type secretsCatalogerProgressAdapter struct {
	*secrets.Monitor
}

// Deprecated: will be removed in syft 1.0
func newSecretsCatalogerProgressAdapter(monitor *secrets.Monitor) secretsCatalogerProgressAdapter {
	return secretsCatalogerProgressAdapter{
		Monitor: monitor,
	}
}

func (s secretsCatalogerProgressAdapter) Stage() string {
	return fmt.Sprintf("%d secrets", s.Monitor.SecretsDiscovered.Current())
}

// Deprecated: will be removed in syft 1.0
func (m *Handler) handleSecretsCatalogerStarted(e partybus.Event) []tea.Model {
	mon, err := syftEventParsers.ParseSecretsCatalogingStarted(e)
	if err != nil {
		log.WithFields("error", err).Warn("unable to parse event")
		return nil
	}

	tsk := m.newTaskProgress(
		taskprogress.Title{
			Default: "Catalog secrets",
			Running: "Cataloging secrets",
			Success: "Cataloged secrets",
		},

		taskprogress.WithStagedProgressable(
			newSecretsCatalogerProgressAdapter(mon),
		),
	)

	tsk.HideStageOnSuccess = false

	return []tea.Model{tsk}
}
