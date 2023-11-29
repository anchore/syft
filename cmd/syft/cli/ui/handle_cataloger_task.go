package ui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/uuid"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/bubbly/bubbles/taskprogress"
	"github.com/anchore/bubbly/bubbles/tree"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event/monitor"
	syftEventParsers "github.com/anchore/syft/syft/event/parsers"
)

type taskModelFactory func(title taskprogress.Title, opts ...taskprogress.Option) taskprogress.Model

var _ tea.Model = (*catalogerTaskState)(nil)

type catalogerTaskState struct {
	model        tree.Model
	modelFactory taskModelFactory
}

func newCatalogerTaskState(f taskModelFactory) *catalogerTaskState {
	t := tree.NewModel()
	t.Padding = "   "
	t.RootsWithoutPrefix = true
	return &catalogerTaskState{
		modelFactory: f,
		model:        t,
	}
}

type catalogerTaskEvent struct {
	info monitor.GenericTask
	prog progress.StagedProgressable
}

func (cts catalogerTaskState) Init() tea.Cmd {
	return cts.model.Init()
}

func (cts catalogerTaskState) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	event, ok := msg.(catalogerTaskEvent)
	if !ok {
		model, cmd := cts.model.Update(msg)
		cts.model = model.(tree.Model)

		return cts, cmd
	}

	info, prog := event.info, event.prog

	tsk := cts.modelFactory(
		taskprogress.Title{
			Default: info.Title.Default,
			Running: info.Title.WhileRunning,
			Success: info.Title.OnSuccess,
		},
		taskprogress.WithStagedProgressable(prog),
	)

	if info.Context != "" {
		tsk.Context = []string{info.Context}
	}

	tsk.HideOnSuccess = info.HideOnSuccess
	tsk.HideStageOnSuccess = info.HideStageOnSuccess
	tsk.HideProgressOnSuccess = true

	if info.ParentID != "" {
		tsk.TitleStyle = lipgloss.NewStyle()
	}

	if err := cts.model.Add(info.ParentID, info.ID, tsk); err != nil {
		log.WithFields("error", err).Error("unable to add cataloger task to tree model")
	}

	return cts, tsk.Init()
}

func (cts catalogerTaskState) View() string {
	return cts.model.View()
}

func (cts catalogerTaskState) onCatalogerTaskStarted(info monitor.GenericTask, prog progress.StagedProgressable) tea.Cmd {
	if info.ID == "" {
		// ID is optional from the consumer perspective, but required internally
		info.ID = uuid.Must(uuid.NewRandom()).String()
	}

	// we need to inject this information into the bubbletea update-render event loop
	return func() tea.Msg {
		return catalogerTaskEvent{
			info: info,
			prog: prog,
		}
	}
}

func (m *Handler) handleCatalogerTaskStarted(e partybus.Event) ([]tea.Model, tea.Cmd) {
	mon, info, err := syftEventParsers.ParseCatalogerTaskStarted(e)
	if err != nil {
		log.WithFields("error", err).Warn("unable to parse event")
		return nil, nil
	}

	var models []tea.Model
	if m.catalogerTasks == nil {
		m.catalogerTasks = newCatalogerTaskState(m.newTaskProgress)
		models = append(models, m.catalogerTasks)
	}

	cmd := m.catalogerTasks.onCatalogerTaskStarted(*info, mon)

	return models, cmd
}
