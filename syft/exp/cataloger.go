package exp

import (
	"fmt"
	"sort"

	"github.com/anchore/syft/internal/capabilities"
	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
)

// Cataloger describes an available cataloger and its selection metadata.
type Cataloger struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

// AllCatalogers returns information about all registered catalogers
// (both package and file catalogers), sorted by name. Any additional
// user-provided cataloger references are included in the result.
func AllCatalogers(additional ...pkgcataloging.CatalogerReference) ([]Cataloger, error) {
	return SelectCatalogers(cataloging.SelectionRequest{
		DefaultNamesOrTags: []string{"all"},
	}, additional...)
}

// SelectCatalogers returns information about catalogers matching the given
// selection request. It applies the same selection logic used by CreateSBOM
// and the "syft cataloger list" CLI command.
//
// Any additional user-provided cataloger references are merged into the
// selectable set before selection is applied. References with AlwaysEnabled
// set to true are always included in the result regardless of the selection.
//
// If the selection request is empty (zero value), no catalogers are returned;
// use AllCatalogers() or pass a selection with DefaultNamesOrTags: []string{"all"}.
func SelectCatalogers(selection cataloging.SelectionRequest, additional ...pkgcataloging.CatalogerReference) ([]Cataloger, error) {
	cfg := task.DefaultCatalogingFactoryConfig()

	pkgTasks, err := task.DefaultPackageTaskFactories().Tasks(cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to create package cataloger tasks: %w", err)
	}

	fileTasks, err := task.DefaultFileTaskFactories().Tasks(cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to create file cataloger tasks: %w", err)
	}

	var persistentTasks []task.Task
	for _, ref := range additional {
		if ref.Cataloger == nil {
			continue
		}
		t := task.NewPackageTask(cfg, ref.Cataloger, ref.Tags...)
		if ref.AlwaysEnabled {
			persistentTasks = append(persistentTasks, t)
		} else {
			pkgTasks = append(pkgTasks, t)
		}
	}

	if selection.IsEmpty() {
		if len(persistentTasks) > 0 {
			return extractCatalogers(persistentTasks), nil
		}
		return nil, nil
	}

	taskGroups := [][]task.Task{pkgTasks, fileTasks}
	selectedGroups, _, err := task.SelectInGroups(taskGroups, selection)
	if err != nil {
		return nil, fmt.Errorf("unable to select catalogers: %w", err)
	}

	var selected []task.Task
	for _, group := range selectedGroups {
		selected = append(selected, group...)
	}
	selected = append(selected, persistentTasks...)

	return extractCatalogers(selected), nil
}

func extractCatalogers(tasks []task.Task) []Cataloger {
	infos := capabilities.ExtractCatalogerInfo(tasks)

	catalogers := make([]Cataloger, 0, len(infos))
	for _, info := range infos {
		tags := info.Selectors
		if tags == nil {
			tags = []string{}
		}
		catalogers = append(catalogers, Cataloger{
			Name: info.Name,
			Tags: tags,
		})
	}

	sort.Slice(catalogers, func(i, j int) bool {
		return catalogers[i].Name < catalogers[j].Name
	})

	return catalogers
}
