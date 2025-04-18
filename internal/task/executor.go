package task

import (
	"context"
	"fmt"
	"runtime/debug"
	"slices"
	"time"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
)

func RunTask(ctx context.Context, tsk Task, resolver file.Resolver, s sbomsync.Builder, prog *monitor.CatalogerTaskProgress) error {
	err := runTaskSafely(ctx, tsk, resolver, s)
	unknowns, remainingErrors := unknown.ExtractCoordinateErrors(err)
	if len(unknowns) > 0 {
		appendUnknowns(s, tsk.Name(), unknowns)
	}
	if remainingErrors != nil {
		prog.SetError(remainingErrors)
	}
	prog.Increment()
	return remainingErrors
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
