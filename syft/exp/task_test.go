package exp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

type taskTestCataloger struct {
	name string
}

func (c taskTestCataloger) Name() string {
	return c.name
}

func (c taskTestCataloger) Catalog(context.Context, file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	return nil, nil, nil
}

func TestSelectCatalogerTasksDoesNotConstructCatalogers(t *testing.T) {
	constructed := 0
	catalogerTask := NewCatalogerTaskFactory("custom-cataloger", func() pkg.Cataloger {
		constructed++
		return taskTestCataloger{name: "custom-cataloger"}
	}, WithTags("custom"))

	selected, err := SelectCatalogerTasks(
		[]Task{catalogerTask},
		cataloging.NewSelectionRequest().WithDefaults("custom"),
	)
	require.NoError(t, err)
	require.Len(t, selected, 1)
	assert.Zero(t, constructed)

	_, _, err = selected[0].Catalog(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, 1, constructed)
}

func TestCatalogerConfigAPIsApplySelection(t *testing.T) {
	config := syft.DefaultCreateSBOMConfig().WithCatalogerSelection(
		cataloging.NewSelectionRequest().
			WithDefaults("all").
			WithSubSelections("python"),
	)

	names, err := ListCatalogers(config)
	require.NoError(t, err)
	assert.Contains(t, names, "python-package-cataloger")
	assert.Contains(t, names, "python-installed-package-cataloger")
	assert.NotContains(t, names, "ruby-gemfile-cataloger")

	info, err := CatalogerInfo(config)
	require.NoError(t, err)
	require.NotEmpty(t, info)
	for _, catalogerInfo := range info {
		if catalogerInfo.Name == "python-package-cataloger" {
			assert.Contains(t, catalogerInfo.Selectors, "python")
			assert.NotEmpty(t, catalogerInfo.Parsers)
			return
		}
	}
	t.Fatal("python-package-cataloger capability information not found")
}

func TestCatalogerInfoDescribesCustomCatalogers(t *testing.T) {
	config := syft.DefaultCreateSBOMConfig().
		WithoutCatalogers().
		WithCatalogers(pkgcataloging.NewCatalogerReference(
			taskTestCataloger{name: "custom-cataloger"},
			[]string{"custom"},
		)).
		WithCatalogerSelection(cataloging.NewSelectionRequest().WithDefaults("custom"))

	info, err := CatalogerInfo(config)
	require.NoError(t, err)
	require.Len(t, info, 1)
	assert.Equal(t, "custom-cataloger", info[0].Name)
	assert.Equal(t, "custom", info[0].Type)
	assert.Contains(t, info[0].Selectors, "custom")
}

func TestSelectCatalogerTasksIncludesAlwaysEnabledTasks(t *testing.T) {
	persistent := NewCatalogerTaskFactory(
		"persistent-cataloger",
		func() pkg.Cataloger { return taskTestCataloger{name: "persistent-cataloger"} },
		AlwaysEnabled(),
	)
	selectable := NewCatalogerTaskFactory(
		"selected-cataloger",
		func() pkg.Cataloger { return taskTestCataloger{name: "selected-cataloger"} },
		WithTags("selected"),
	)

	selected, err := SelectCatalogerTasks(
		[]Task{persistent, selectable},
		cataloging.NewSelectionRequest().WithDefaults("selected"),
	)
	require.NoError(t, err)
	require.Len(t, selected, 2)
	assert.Equal(t, "selected-cataloger", selected[0].Name())
	assert.Equal(t, "persistent-cataloger", selected[1].Name())
}

func TestTaskCapabilitiesReturnsCopies(t *testing.T) {
	input := Capabilities{
		Selectors: []string{"custom"},
		Capabilities: CapabilitySet{
			{Default: []any{map[string]any{"key": "value"}}},
		},
	}
	catalogerTask := NewCatalogerTaskFactory(
		"custom-cataloger",
		func() pkg.Cataloger { return taskTestCataloger{name: "custom-cataloger"} },
		WithTags("custom"),
		WithCapabilities(input),
	)

	first, ok := catalogerTask.Capabilities()
	require.True(t, ok)
	first.Selectors[0] = "changed"
	first.Capabilities[0].Default.([]any)[0].(map[string]any)["key"] = "changed"

	second, ok := catalogerTask.Capabilities()
	require.True(t, ok)
	assert.Contains(t, second.Selectors, "custom")
	assert.Equal(t, "value", second.Capabilities[0].Default.([]any)[0].(map[string]any)["key"])
	assert.Equal(t, "value", input.Capabilities[0].Default.([]any)[0].(map[string]any)["key"])
}
