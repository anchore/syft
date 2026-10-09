package task

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

type catalogerTaskTestCataloger struct {
	name string
}

func (c catalogerTaskTestCataloger) Name() string {
	return c.name
}

func (c catalogerTaskTestCataloger) Catalog(context.Context, file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	return nil, nil, nil
}

func TestSelectCatalogerTasksDoesNotConstructCatalogers(t *testing.T) {
	constructed := 0
	catalogerTask := NewCatalogerTaskFactory("custom-cataloger", func() pkg.Cataloger {
		constructed++
		return catalogerTaskTestCataloger{name: "custom-cataloger"}
	}, "custom")

	selected, err := SelectCatalogerTasks(
		CatalogerTasks{catalogerTask},
		cataloging.NewSelectionRequest().WithDefaults("custom"),
	)
	require.NoError(t, err)
	require.Len(t, selected, 1)
	assert.Zero(t, constructed)

	_, _, err = selected[0].Catalog(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, 1, constructed)
}

func TestSelectCatalogerTasksIncludesAlwaysEnabledTasks(t *testing.T) {
	persistent := NewCatalogerTaskFactory(
		"persistent-cataloger",
		func() pkg.Cataloger { return catalogerTaskTestCataloger{name: "persistent-cataloger"} },
	).WithAlwaysEnabled()
	selectable := NewCatalogerTaskFactory(
		"selected-cataloger",
		func() pkg.Cataloger { return catalogerTaskTestCataloger{name: "selected-cataloger"} },
		"selected",
	)

	selected, err := SelectCatalogerTasks(
		CatalogerTasks{persistent, selectable},
		cataloging.NewSelectionRequest().WithDefaults("selected"),
	)
	require.NoError(t, err)
	require.Len(t, selected, 2)
	assert.Equal(t, "selected-cataloger", selected[0].Name())
	assert.Equal(t, "persistent-cataloger", selected[1].Name())
}

func TestCatalogerTasksValidateNames(t *testing.T) {
	tests := []struct {
		name    string
		tasks   CatalogerTasks
		wantErr string
	}{
		{
			name: "valid",
			tasks: CatalogerTasks{
				NewCatalogerTaskFactory("one", nil),
				NewCatalogerTaskFactory("two", nil),
			},
		},
		{
			name:    "empty name",
			tasks:   CatalogerTasks{NewCatalogerTaskFactory("", nil)},
			wantErr: "cataloger task without a name",
		},
		{
			name: "duplicate name",
			tasks: CatalogerTasks{
				NewCatalogerTaskFactory("duplicate", nil),
				NewCatalogerTaskFactory("duplicate", nil),
			},
			wantErr: "duplicate cataloger task names: duplicate",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.tasks.Validate()
			if test.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, test.wantErr)
		})
	}
}
