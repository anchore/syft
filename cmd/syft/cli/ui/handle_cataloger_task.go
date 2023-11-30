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

// we standardize how rows are instantiated to ensure consistency in the appearance across the UI
type taskModelFactory func(title taskprogress.Title, opts ...taskprogress.Option) taskprogress.Model

var _ tea.Model = (*catalogerTaskModel)(nil)

type catalogerTaskModel struct {
	model        tree.Model
	modelFactory taskModelFactory
}

func newCatalogerTaskTreeModel(f taskModelFactory) *catalogerTaskModel {
	t := tree.NewModel()
	t.Padding = "   "
	t.RootsWithoutPrefix = true
	return &catalogerTaskModel{
		modelFactory: f,
		model:        t,
	}
}

type newCatalogerTaskRowEvent struct {
	info monitor.GenericTask
	prog progress.StagedProgressable
}

func (cts catalogerTaskModel) Init() tea.Cmd {
	return cts.model.Init()
}

func (cts catalogerTaskModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	event, ok := msg.(newCatalogerTaskRowEvent)
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

func (cts catalogerTaskModel) View() string {
	return cts.model.View()
}

func (m *Handler) handleCatalogerTaskStarted(e partybus.Event) ([]tea.Model, tea.Cmd) {
	mon, info, err := syftEventParsers.ParseCatalogerTaskStarted(e)
	if err != nil {
		log.WithFields("error", err).Warn("unable to parse event")
		return nil, nil
	}

	var models []tea.Model

	// only create the new cataloger task tree once to manage all cataloger task events
	m.onNewCatalogerTask.Do(func() {
		models = append(models, newCatalogerTaskTreeModel(m.newTaskProgress))
	})

	// we need to update the cataloger task model with a new row. We should never update the model outside of the
	// bubbletea update-render event loop. Instead, we return a command that will be executed by the bubbletea runtime,
	// producing a message that is passed to the cataloger task model. This is the prescribed way to update models
	// in bubbletea.

	if info.ID == "" {
		// ID is optional from the consumer perspective, but required internally
		info.ID = uuid.Must(uuid.NewRandom()).String()
	}

	cmd := func() tea.Msg {
		// this message will cause the cataloger task model to add a new row to the output based on the given task
		// information and progress data.
		return newCatalogerTaskRowEvent{
			info: *info,
			prog: mon,
		}
	}

	return models, cmd
}
