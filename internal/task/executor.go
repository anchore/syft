package task

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"

	"github.com/hashicorp/go-multierror"

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
	var errs error
	wg := &sync.WaitGroup{}
	for i := 0; i < p.numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for {
				tsk, ok := <-p.tasks
				if !ok {
					return
				}

				if err := runTaskSafely(ctx, tsk, resolver, s); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("failed to run task: %w", err))
					prog.SetError(err)
				}
				prog.Increment()
			}
		}()
	}

	wg.Wait()

	return errs
}

func runTaskSafely(ctx context.Context, t Task, resolver file.Resolver, s sbomsync.Builder) (err error) {
	// handle individual cataloger panics
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v at:\n%s", e, string(debug.Stack()))
		}
	}()

	return t.Execute(ctx, resolver, s)
}
