package bus

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/syft/syft/event/monitor"
)

func digestsTask() monitor.GenericTask {
	return monitor.GenericTask{
		Title:    monitor.Title{Default: "File digests"},
		ParentID: monitor.TopLevelCatalogingTaskID,
	}
}

func TestStartCatalogerTask_withoutARegistryEveryRunPublishes(t *testing.T) {
	// the right answer for a caller driving a single pass: nothing re-runs, so nothing should be reused
	ctx := context.Background()

	first := StartCatalogerTask(ctx, digestsTask(), 2, "")
	second := StartCatalogerTask(ctx, digestsTask(), 3, "")

	assert.NotSame(t, first, second)
	assert.Equal(t, int64(2), first.Size())
	assert.Equal(t, int64(3), second.Size())
}

func TestStartCatalogerTask_reRunReportsIntoTheRowItAlreadyOwns(t *testing.T) {
	ctx := WithCatalogerTaskRegistry(context.Background())

	first := StartCatalogerTask(ctx, digestsTask(), 2, "")
	first.Increment()
	first.Increment()
	first.SetCompleted()

	// the archive walk reaches the same cataloger again, over an archive's contents this time
	second := StartCatalogerTask(ctx, digestsTask(), 3, "")
	require.Same(t, first, second, "a re-run must find the row it already published")

	assert.Equal(t, int64(5), second.Size(), "the total must cover both runs, not just the first")
	assert.False(t, progress.IsCompleted(second), "a row with work still to do must not read as complete")

	for i := 0; i < 3; i++ {
		second.Increment()
	}
	second.SetCompleted()

	assert.Equal(t, int64(5), second.Current())
	assert.Equal(t, int64(5), second.Size(), "the count must not run past the total")
	assert.True(t, progress.IsCompleted(second))
}

func TestStartCatalogerTask_aTotalResolvedOnCompletionIsAddable(t *testing.T) {
	// a run that could not say how much it would do says so when it signs off (Manual.SetCompleted
	// backfills the total from the count), so by the time a re-run arrives there is a real number to
	// add to. This is the file metadata cataloger's shape: it publishes -1 every run.
	ctx := WithCatalogerTaskRegistry(context.Background())

	row := StartCatalogerTask(ctx, digestsTask(), -1, "")
	row.Increment()
	row.SetCompleted()
	require.Equal(t, int64(1), row.Size(), "signing off must resolve the total to what the run did")

	require.Same(t, row, StartCatalogerTask(ctx, digestsTask(), -1, ""))
	assert.Equal(t, int64(-1), row.Size(), "a re-run that cannot say its own size makes the row indeterminate again")

	row.Increment()
	row.SetCompleted()
	assert.Equal(t, int64(2), row.Current())
	assert.Equal(t, int64(2), row.Size(), "and signing off resolves it again, over both runs")
}

func TestStartCatalogerTask_indeterminateTotalsStayIndeterminate(t *testing.T) {
	// a run whose size is unknown cannot be added to one that is known
	tests := []struct {
		name        string
		first, next int64
		complete    func(row *monitor.TaskProgress)
	}{
		{
			name:  "the re-run cannot say its own size",
			first: 2, next: -1,
			complete: func(row *monitor.TaskProgress) { row.Increment(); row.SetCompleted() },
		},
		{
			name:  "the first run did nothing, so completing resolved nothing",
			first: -1, next: 3,
			complete: func(row *monitor.TaskProgress) { row.SetCompleted() },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithCatalogerTaskRegistry(context.Background())

			row := StartCatalogerTask(ctx, digestsTask(), tt.first, "")
			tt.complete(row)

			require.Same(t, row, StartCatalogerTask(ctx, digestsTask(), tt.next, ""))
			assert.Equal(t, int64(-1), row.Size())
			assert.False(t, progress.IsCompleted(row), "an indeterminate row is not complete until it says so")
		})
	}
}

func TestStartCatalogerTask_aFailedRowKeepsItsFailure(t *testing.T) {
	// a later run finding nothing wrong does not mean the earlier one succeeded
	ctx := WithCatalogerTaskRegistry(context.Background())
	failure := errors.New("unable to read the thing")

	row := StartCatalogerTask(ctx, digestsTask(), 2, "")
	row.SetError(failure)

	require.Same(t, row, StartCatalogerTask(ctx, digestsTask(), 3, ""))
	assert.ErrorIs(t, row.Error(), failure)
}

func TestStartCatalogerTask_rowsAreKeyedByTaskIdentity(t *testing.T) {
	ctx := WithCatalogerTaskRegistry(context.Background())

	byID := func(id string) monitor.GenericTask {
		return monitor.GenericTask{ID: id, Title: monitor.Title{Default: "shared title"}}
	}

	assert.Same(t, StartCatalogerTask(ctx, byID("a"), -1, ""), StartCatalogerTask(ctx, byID("a"), -1, ""))
	assert.NotSame(t, StartCatalogerTask(ctx, byID("a"), -1, ""), StartCatalogerTask(ctx, byID("b"), -1, ""),
		"an ID is the identity where there is one, even when two tasks share a title")

	// a task publishing without an ID, as every file cataloger does, is keyed by where it sits and what
	// it is called
	underCataloging := monitor.GenericTask{Title: monitor.Title{Default: "Files"}, ParentID: "cataloging"}
	underSomethingElse := monitor.GenericTask{Title: monitor.Title{Default: "Files"}, ParentID: "other"}

	assert.Same(t, StartCatalogerTask(ctx, underCataloging, -1, ""), StartCatalogerTask(ctx, underCataloging, -1, ""))
	assert.NotSame(t, StartCatalogerTask(ctx, underCataloging, -1, ""), StartCatalogerTask(ctx, underSomethingElse, -1, ""))
}

func TestWithCatalogerTaskRegistry_isIdempotent(t *testing.T) {
	// anything that re-runs catalogers may ask for a registry; a second one would hold none of the rows
	// already published and every re-run would publish again
	ctx := WithCatalogerTaskRegistry(context.Background())
	row := StartCatalogerTask(ctx, digestsTask(), 2, "")

	nested := WithCatalogerTaskRegistry(ctx)
	assert.Same(t, row, StartCatalogerTask(nested, digestsTask(), 2, ""))
}
