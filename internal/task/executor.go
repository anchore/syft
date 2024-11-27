package task

import (
	"context"
	"fmt"
	"runtime/debug"
	"slices"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
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
	var lock sync.Mutex
	withLock := func(fn func()) {
		lock.Lock()
		defer lock.Unlock()
		fn()
	}
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

				err := runTaskSafely(ctx, tsk, resolver, s)
				unknowns, remainingErrors := unknown.ExtractCoordinateErrors(err)
				if len(unknowns) > 0 {
					appendUnknowns(s, tsk.Name(), unknowns)
				}
				if remainingErrors != nil {
					withLock(func() {
						errs = multierror.Append(errs, fmt.Errorf("failed to run task: %w", remainingErrors))
						prog.SetError(remainingErrors)
					})
				}
				prog.Increment()
			}
		}()
	}

	wg.Wait()

	return errs
}

func appendUnknowns(builder sbomsync.Builder, taskName string, unknowns []unknown.CoordinateError) {
	if accessor, ok := builder.(sbomsync.Accessor); ok {
		accessor.WriteToSBOM(func(sb *sbom.SBOM) {
			for _, u := range unknowns {
				if sb.Artifacts.Unknowns == nil {
					sb.Artifacts.Unknowns = map[file.Coordinates][]string{}
				}
				unknownText := formatUnknown(u.Reason.Error(), taskName)
				existing := sb.Artifacts.Unknowns[u.Coordinates]
				// don't include duplicate unknowns
				if slices.Contains(existing, unknownText) {
					continue
				}
				sb.Artifacts.Unknowns[u.Coordinates] = append(existing, unknownText)
			}
		})
	}
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
