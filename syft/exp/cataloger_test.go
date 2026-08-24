package exp

import (
	"context"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

type dummyCataloger struct {
	name string
}

func (d dummyCataloger) Name() string { return d.name }
func (d dummyCataloger) Catalog(_ context.Context, _ file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	return nil, nil, nil
}

type staticProvider struct {
	tasks     []Task
	selection cataloging.SelectionRequest
}

func (p staticProvider) CatalogerTasks() ([]Task, error) {
	return p.tasks, nil
}

func (p staticProvider) CatalogerSelectionRequest() cataloging.SelectionRequest {
	return p.selection
}

func TestAllCatalogers(t *testing.T) {
	catalogers, err := AllCatalogers()
	require.NoError(t, err)
	assert.Greater(t, len(catalogers), 10)

	for i := 1; i < len(catalogers); i++ {
		assert.LessOrEqual(t, catalogers[i-1].Name, catalogers[i].Name, "results should be sorted by name")
	}

	names := make(map[string]bool)
	for _, c := range catalogers {
		assert.NotEmpty(t, c.Name)
		assert.Contains(t, c.Tags, pkgcataloging.PackageTag)
		names[c.Name] = true
	}

	assert.True(t, names["python-installed-package-cataloger"], "should contain python-installed-package-cataloger")
	assert.True(t, names["go-module-binary-cataloger"], "should contain go-module-binary-cataloger")
}

func TestSelectCatalogers(t *testing.T) {
	t.Run("with filter", func(t *testing.T) {
		selection := cataloging.NewSelectionRequest().
			WithDefaults("all").
			WithSubSelections("python")

		catalogers, err := SelectCatalogers(selection)
		require.NoError(t, err)
		assert.Greater(t, len(catalogers), 0)

		for _, c := range catalogers {
			assert.True(t, slices.Contains(c.Tags, "python"), "cataloger %q should have python tag", c.Name)
		}
	})

	t.Run("empty selection returns all package catalogers", func(t *testing.T) {
		catalogers, err := SelectCatalogers(cataloging.SelectionRequest{})
		require.NoError(t, err)
		assert.Greater(t, len(catalogers), 10)
	})

	t.Run("with additional always-enabled cataloger", func(t *testing.T) {
		ref := pkgcataloging.CatalogerReference{
			Cataloger:     dummyCataloger{name: "my-custom-cataloger"},
			AlwaysEnabled: true,
			Tags:          []string{"custom"},
		}

		catalogers, err := SelectCatalogers(
			cataloging.NewSelectionRequest().WithDefaults("all"),
			ref,
		)
		require.NoError(t, err)

		found := slices.ContainsFunc(catalogers, func(c Cataloger) bool {
			return c.Name == "my-custom-cataloger"
		})
		assert.True(t, found, "should include the always-enabled custom cataloger")
	})

	t.Run("with additional selectable cataloger matching selection", func(t *testing.T) {
		ref := pkgcataloging.CatalogerReference{
			Cataloger: dummyCataloger{name: "my-python-cataloger"},
			Tags:      []string{"python", "custom"},
		}

		catalogers, err := SelectCatalogers(
			cataloging.NewSelectionRequest().WithDefaults("all").WithSubSelections("custom"),
			ref,
		)
		require.NoError(t, err)

		found := slices.ContainsFunc(catalogers, func(c Cataloger) bool {
			return c.Name == "my-python-cataloger"
		})
		assert.True(t, found, "should include custom cataloger that matches selection")
	})

	t.Run("with additional selectable cataloger not matching selection", func(t *testing.T) {
		ref := pkgcataloging.CatalogerReference{
			Cataloger: dummyCataloger{name: "my-ruby-cataloger"},
			Tags:      []string{"ruby", "custom"},
		}

		catalogers, err := SelectCatalogers(
			cataloging.NewSelectionRequest().WithDefaults("all").WithSubSelections("python"),
			ref,
		)
		require.NoError(t, err)

		found := slices.ContainsFunc(catalogers, func(c Cataloger) bool {
			return c.Name == "my-ruby-cataloger"
		})
		assert.False(t, found, "should not include custom cataloger that does not match selection")
	})

	t.Run("always-enabled cataloger included with empty selection", func(t *testing.T) {
		ref := pkgcataloging.CatalogerReference{
			Cataloger:     dummyCataloger{name: "my-persistent-cataloger"},
			AlwaysEnabled: true,
			Tags:          []string{"custom"},
		}

		catalogers, err := SelectCatalogers(cataloging.SelectionRequest{}, ref)
		require.NoError(t, err)

		found := slices.ContainsFunc(catalogers, func(c Cataloger) bool {
			return c.Name == "my-persistent-cataloger"
		})
		assert.True(t, found)
	})
}

func TestSelectCatalogerTasksDoesNotConstructCatalogers(t *testing.T) {
	constructed := 0
	task := NewCatalogerTaskFactory("custom-cataloger", func() pkg.Cataloger {
		constructed++
		return dummyCataloger{name: "custom-cataloger"}
	}, WithTags("custom"))

	selected, err := SelectCatalogerTasks([]Task{task}, cataloging.NewSelectionRequest().WithDefaults("custom"))
	require.NoError(t, err)
	require.Len(t, selected, 1)
	assert.Zero(t, constructed)

	assert.NotNil(t, selected[0].Cataloger())
	assert.Equal(t, 1, constructed)
}

func TestCatalogerInfo(t *testing.T) {
	capabilities := Capabilities{
		Name: "custom-cataloger",
		Type: "custom",
		Detectors: []Detector{
			{
				Method:   GlobDetection,
				Criteria: []string{"**/custom.lock"},
			},
		},
	}
	task := NewCatalogerTaskFactory(
		"custom-cataloger",
		func() pkg.Cataloger { return dummyCataloger{name: "custom-cataloger"} },
		WithTags("custom"),
		WithCapabilities(capabilities),
	)

	info, err := CatalogerInfo(staticProvider{tasks: []Task{task}})
	require.NoError(t, err)
	require.Len(t, info, 1)
	assert.Equal(t, "custom-cataloger", info[0].Name)
	assert.Contains(t, info[0].Selectors, "custom")
	require.Len(t, info[0].Detectors, 1)
	assert.Equal(t, GlobDetection, info[0].Detectors[0].Method)
}

func TestListCatalogers(t *testing.T) {
	tasks := []Task{
		NewCatalogerTaskFactory("custom-a", func() pkg.Cataloger { return dummyCataloger{name: "custom-a"} }, WithTags("custom")),
		NewCatalogerTaskFactory("custom-b", func() pkg.Cataloger { return dummyCataloger{name: "custom-b"} }, WithTags("other")),
	}

	names, err := ListCatalogers(staticProvider{
		tasks:     tasks,
		selection: cataloging.NewSelectionRequest().WithDefaults("custom"),
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"custom-a"}, names)
}
