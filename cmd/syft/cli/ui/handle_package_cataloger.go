package ui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/bubbly/bubbles/taskprogress"
	"github.com/anchore/syft/internal/log"
	syftEventParsers "github.com/anchore/syft/syft/event/parsers"
	"github.com/anchore/syft/syft/pkg/cataloger"
)

var _ progress.StagedProgressable = (*packageCatalogerProgressAdapter)(nil)

type packageCatalogerProgressAdapter struct {
	monitor  *cataloger.Monitor
	monitors []progress.Monitorable
}

func newPackageCatalogerProgressAdapter(monitor *cataloger.Monitor) packageCatalogerProgressAdapter {
	return packageCatalogerProgressAdapter{
		monitor: monitor,
		monitors: []progress.Monitorable{
			monitor.FilesProcessed,
			monitor.PackagesDiscovered,
		},
	}
}

func (p packageCatalogerProgressAdapter) Stage() string {
	return fmt.Sprintf("%d packages", p.monitor.PackagesDiscovered.Current())
}

func (p packageCatalogerProgressAdapter) Current() int64 {
	return p.monitor.PackagesDiscovered.Current()
}

func (p packageCatalogerProgressAdapter) Error() error {
	completedMonitors := 0
	for _, monitor := range p.monitors {
		err := monitor.Error()
		if err == nil {
			continue
		}
		if progress.IsErrCompleted(err) {
			completedMonitors++
			continue
		}
		// something went wrong
		return err
	}
	if completedMonitors == len(p.monitors) && len(p.monitors) > 0 {
		return p.monitors[0].Error()
	}
	return nil
}

func (p packageCatalogerProgressAdapter) Size() int64 {
	// this is an inherently unknown value (indeterminate total number of packages to discover)
	return -1
}

func (m *Handler) handlePackageCatalogerStarted(e partybus.Event) []tea.Model {
	monitor, err := syftEventParsers.ParsePackageCatalogerStarted(e)
	if err != nil {
		log.WithFields("error", err).Warn("unable to parse event")
		return nil
	}

	tsk := m.newTaskProgress(
		taskprogress.Title{
			Default: "Catalog packages",
			Running: "Cataloging packages",
			Success: "Cataloged packages",
		},
		taskprogress.WithStagedProgressable(
			newPackageCatalogerProgressAdapter(monitor),
		),
	)

	tsk.HideStageOnSuccess = false

	return []tea.Model{tsk}
}
