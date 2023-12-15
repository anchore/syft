package task

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/file"
)

func Test_TaskExecutor_PanicHandling(t *testing.T) {
	tsk := NewTask("panicking-cataloger", func(_ file.Resolver, _ sbomsync.Builder) error {
		panic("something bad happened")
	})
	ex := NewTaskExecutor([]Task{tsk}, 1)

	err := ex.Execute(nil, nil, &monitor.CatalogerTaskProgress{
		Manual: progress.NewManual(-1),
	})

	require.Error(t, err)
	require.Contains(t, err.Error(), "executor_test.go")
}
