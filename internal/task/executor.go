package task

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/hashicorp/go-multierror"

	"github.com/anchore/go-sync"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/file"
)

type Executor struct {
	numWorkers int
	tasks      chan Task
}

func NewTaskExecutor(tasks []Task, numWorkers int) *Executor {
	p := &Executor{
		numWorkers: numWorkers,
		tasks:      make(chan Task, len(tasks)),
	}

	for i := range tasks {
		p.tasks <- tasks[i]
	}
	close(p.tasks)

	return p
}

func (p *Executor) Execute(ctx context.Context, resolver file.Resolver, s sbomsync.Builder, prog *monitor.CatalogerTaskProgress) error {
	exec := sync.ContextExecutor(ctx)

	collector := sync.NewCollector[error](exec)

	run := func(tsk Task) sync.ProviderFunc[error] {
		return func() error {
			if err := runTaskSafely(ctx, tsk, resolver, s); err != nil {
				prog.SetError(err)
				return err
			}
			prog.Increment()
			return nil
		}
	}

	for {
		tsk, ok := <-p.tasks
		if !ok {
			break
		}

		collector.Provide(run(tsk))
	}

	errs := collector.Collect()

	if len(errs) == 0 {
		return nil
	}

	var nonNilErrs []error
	for _, err := range errs {
		if err != nil {
			nonNilErrs = append(nonNilErrs, err)
		}
	}

	if len(nonNilErrs) == 0 {
		return nil
	}

	return multierror.Append(nil, nonNilErrs...)
}

func runTaskSafely(ctx context.Context, t Task, resolver file.Resolver, s sbomsync.Builder) (err error) {
	// handle individual cataloger panics
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v at:\n%s", e, string(debug.Stack()))
		}
	}()

	start := time.Now()
	res := t.Execute(ctx, resolver, s)
	log.WithFields("task", t.Name(), "elapsed", time.Since(start)).Info("task completed")
	return res
}
