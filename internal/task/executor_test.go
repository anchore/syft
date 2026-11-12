package task

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/sbom"
)

func Test_TaskExecutor_PanicHandling(t *testing.T) {
	tsk := NewTask("panicking-cataloger", func(_ context.Context, _ file.Resolver, _ sbomsync.Builder) error {
		panic("something bad happened")
	})

	err := RunTask(context.Background(), tsk, nil, nil, &monitor.TaskProgress{
		Manual: progress.NewManual(-1),
	})

	require.EqualError(t, err, `panic in task "panicking-cataloger": something bad happened`)
}

func Test_RunTask_GenericParserPanicBecomesUnknown(t *testing.T) {
	c := generic.NewCataloger("panicking-cataloger").
		WithParserByPath(func(context.Context, file.Resolver, *generic.Environment, file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
			panic("boom")
		}, "executor_test.go")
	s := &sbom.SBOM{}

	err := RunTask(context.Background(), NewPackageTask(DefaultCatalogingFactoryConfig(), c), file.NewMockResolverForPaths("executor_test.go"), sbomsync.NewBuilder(s), &monitor.TaskProgress{
		Manual: progress.NewManual(-1),
	})

	require.NoError(t, err)
	require.Len(t, s.Artifacts.Unknowns, 1)
}
