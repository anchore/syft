package bus

import (
	"context"

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

type catalogerTaskProgressKey struct{}

// WithCatalogerTaskProgress returns a context whose cataloger tasks report into prog rather than
// starting a row of their own.
//
// Nested cataloging runs under such a context: re-running the cataloger pipeline against the
// contents of an archive is work that belongs to the progress of the task driving the recursion, not
// a second start of every cataloger. Starting rows again per archive floods a consumer's display,
// and where the new row carries an ID the consumer has already seen (every package cataloger does -
// the ID is the cataloger name) it replaces the live row for that ID. The replaced row is then never
// rendered again, its completion is never observed, and a UI that waits on every row it started - as
// the syft CLI does - blocks forever on teardown.
func WithCatalogerTaskProgress(ctx context.Context, prog *monitor.TaskProgress) context.Context {
	return context.WithValue(ctx, catalogerTaskProgressKey{}, prog)
}

// catalogerTaskProgressFromContext returns the progress that cataloger tasks started under this
// context report into, or nil when they should start one of their own.
func catalogerTaskProgressFromContext(ctx context.Context) *monitor.TaskProgress {
	prog, _ := ctx.Value(catalogerTaskProgressKey{}).(*monitor.TaskProgress)
	return prog
}

func StartCatalogerTask(ctx context.Context, info monitor.GenericTask, size int64, initialStage string) *monitor.TaskProgress {
	if parent := catalogerTaskProgressFromContext(ctx); parent != nil {
		// the stage is shared, so what this cataloger is working on shows up on the row already on
		// screen; the count is not, so this task completing does not complete the row it reports into
		return &monitor.TaskProgress{
			AtomicStage: parent.AtomicStage,
			Manual:      progress.NewManual(size),
		}
	}

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
