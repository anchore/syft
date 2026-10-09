package bus

import (
	"context"
	"sync"

	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/clio"
	"github.com/anchore/syft/internal/redact"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/event/monitor"
)

func Exit() {
	Publish(clio.ExitEvent(false))
}

func ExitWithInterrupt() {
	Publish(clio.ExitEvent(true))
}

func Report(report string) {
	if len(report) == 0 {
		return
	}
	report = redact.Apply(report)
	Publish(partybus.Event{
		Type:  event.CLIReport,
		Value: report,
	})
}

func Notify(message string) {
	Publish(partybus.Event{
		Type:  event.CLINotification,
		Value: message,
	})
}

type catalogerTaskRegistryKey struct{}

// catalogerTaskRegistry remembers the progress row each cataloger publishes. A cataloger runs once
// over the scan root and again inside every archive the archive cataloger walks; a re-run reports
// into the row it already owns rather than publishing another, and republishing an ID would replace
// the live row with one the UI never sees completed.
type catalogerTaskRegistry struct {
	mu   sync.Mutex
	rows map[string]*monitor.TaskProgress
}

// WithCatalogerTaskRegistry returns a context under which each cataloger publishes one progress row
// however many times it runs. A context that already carries a registry is returned unchanged.
func WithCatalogerTaskRegistry(ctx context.Context) context.Context {
	if catalogerTaskRegistryFromContext(ctx) != nil {
		return ctx
	}
	return context.WithValue(ctx, catalogerTaskRegistryKey{}, &catalogerTaskRegistry{
		rows: make(map[string]*monitor.TaskProgress),
	})
}

func catalogerTaskRegistryFromContext(ctx context.Context) *catalogerTaskRegistry {
	reg, _ := ctx.Value(catalogerTaskRegistryKey{}).(*catalogerTaskRegistry)
	return reg
}

// catalogerTaskKey identifies the row a task owns: its ID when it has one, otherwise its parent and
// title (file catalogers publish no ID).
func catalogerTaskKey(info monitor.GenericTask) string {
	if info.ID != "" {
		return "id:" + info.ID
	}
	return "title:" + info.ParentID + "/" + info.Title.Default
}

func StartCatalogerTask(ctx context.Context, info monitor.GenericTask, size int64, initialStage string) *monitor.TaskProgress {
	reg := catalogerTaskRegistryFromContext(ctx)
	if reg == nil {
		return publishCatalogerTask(info, size, initialStage)
	}

	reg.mu.Lock()
	defer reg.mu.Unlock()

	key := catalogerTaskKey(info)
	if row, ok := reg.rows[key]; ok {
		resumeCatalogerTask(row, size, initialStage)
		return row
	}

	t := publishCatalogerTask(info, size, initialStage)
	reg.rows[key] = t

	return t
}

// resumeCatalogerTask reopens a row an earlier run completed and grows its total by what this run
// adds, so the row does not read as finished mid-walk. A row carrying a real failure keeps it.
func resumeCatalogerTask(row *monitor.TaskProgress, size int64, initialStage string) {
	if size < 0 || row.Size() < 0 {
		row.SetTotal(-1)
	} else {
		row.SetTotal(row.Size() + size)
	}

	if progress.IsErrCompleted(row.Error()) {
		row.SetError(nil)
	}

	if initialStage != "" {
		row.AtomicStage.Set(initialStage)
	}
}

func publishCatalogerTask(info monitor.GenericTask, size int64, initialStage string) *monitor.TaskProgress {
	t := &monitor.TaskProgress{
		AtomicStage: progress.NewAtomicStage(initialStage),
		Manual:      progress.NewManual(size),
	}

	Publish(partybus.Event{
		Type:   event.CatalogerTaskStarted,
		Source: info,
		Value:  progress.StagedProgressable(t),
	})

	return t
}

func StartPullSourceTask(info monitor.GenericTask, size int64, initialStage string) *monitor.TaskProgress {
	t := &monitor.TaskProgress{
		AtomicStage: progress.NewAtomicStage(initialStage),
		Manual:      progress.NewManual(size),
	}

	Publish(partybus.Event{
		Type:   event.PullSourceStarted,
		Source: info,
		Value:  progress.StagedProgressable(t),
	})

	return t
}

func StartIndexingFiles(path string) *monitor.TaskProgress {
	t := &monitor.TaskProgress{
		AtomicStage: progress.NewAtomicStage(""),
		Manual:      progress.NewManual(-1),
	}

	Publish(partybus.Event{
		Type:   event.FileIndexingStarted,
		Source: path,
		Value:  progress.StagedProgressable(t),
	})

	return t
}
