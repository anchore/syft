package task

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// CatalogerTask describes a package cataloger before it is constructed.
type CatalogerTask struct {
	name             string
	tags             []string
	catalogerFactory func() pkg.Cataloger
	alwaysEnabled    bool
}

// CatalogerTasks is a collection of package cataloger tasks.
type CatalogerTasks []CatalogerTask

// NewCatalogerTask creates a task for an existing package cataloger.
func NewCatalogerTask(cataloger pkg.Cataloger, tags ...string) CatalogerTask {
	if cataloger == nil {
		return CatalogerTask{}
	}

	return NewCatalogerTaskFactory(cataloger.Name(), func() pkg.Cataloger {
		return cataloger
	}, tags...)
}

// NewCatalogerTaskFactory creates a task that constructs its cataloger when it runs.
func NewCatalogerTaskFactory(name string, catalogerFactory func() pkg.Cataloger, tags ...string) CatalogerTask {
	return CatalogerTask{
		name:             name,
		tags:             cleanCatalogerTaskTags(name, append(tags, pkgcataloging.PackageTag)),
		catalogerFactory: catalogerFactory,
	}
}

// WithTags returns a copy of the task with additional selection tags.
func (t CatalogerTask) WithTags(tags ...string) CatalogerTask {
	t.tags = cleanCatalogerTaskTags(t.name, append(slices.Clone(t.tags), tags...))
	return t
}

// WithAlwaysEnabled returns a copy of the task that selection cannot remove.
func (t CatalogerTask) WithAlwaysEnabled() CatalogerTask {
	t.alwaysEnabled = true
	return t
}

// Name returns the package cataloger name.
func (t CatalogerTask) Name() string {
	return t.name
}

// Tags returns the cataloger selection tags.
func (t CatalogerTask) Tags() []string {
	return slices.Clone(t.tags)
}

// AlwaysEnabled reports whether selection requests can remove the task.
func (t CatalogerTask) AlwaysEnabled() bool {
	return t.alwaysEnabled
}

// Catalog constructs and runs the package cataloger.
func (t CatalogerTask) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	if t.catalogerFactory == nil {
		return nil, nil, fmt.Errorf("cataloger task %q has no cataloger factory", t.name)
	}

	cataloger := t.catalogerFactory()
	if cataloger == nil {
		return nil, nil, fmt.Errorf("cataloger task %q constructed a nil cataloger", t.name)
	}

	return cataloger.Catalog(ctx, resolver)
}

// Validate checks that all tasks have unique, non-empty names.
func (t CatalogerTasks) Validate() error {
	seen := strset.New()
	duplicates := strset.New()
	for _, catalogerTask := range t {
		name := catalogerTask.Name()
		if name == "" {
			return fmt.Errorf("cataloger task without a name")
		}
		if seen.Has(name) {
			duplicates.Add(name)
		}
		seen.Add(name)
	}

	if duplicates.Size() == 0 {
		return nil
	}

	names := duplicates.List()
	sort.Strings(names)
	return fmt.Errorf("duplicate cataloger task names: %s", strings.Join(names, ", "))
}

// SelectCatalogerTasks returns matching tasks without constructing catalogers.
func SelectCatalogerTasks(tasks CatalogerTasks, selection cataloging.SelectionRequest) (CatalogerTasks, error) {
	if err := tasks.Validate(); err != nil {
		return nil, err
	}

	var selectable CatalogerTasks
	var persistent CatalogerTasks
	for _, catalogerTask := range tasks {
		if catalogerTask.AlwaysEnabled() {
			persistent = append(persistent, catalogerTask)
			continue
		}
		selectable = append(selectable, catalogerTask)
	}

	if selection.IsEmpty() {
		return append(selectable, persistent...), nil
	}

	selectionTasks := make([]Task, 0, len(selectable))
	for _, catalogerTask := range selectable {
		selectionTasks = append(selectionTasks, newCatalogerSelectionTask(catalogerTask))
	}

	selectedTasks, _, err := Select(selectionTasks, selection)
	if err != nil {
		return nil, fmt.Errorf("unable to select catalogers: %w", err)
	}

	selectedNames := strset.New()
	for _, selectedTask := range selectedTasks {
		selectedNames.Add(selectedTask.Name())
	}

	result := make(CatalogerTasks, 0, len(selectedTasks)+len(persistent))
	for _, catalogerTask := range selectable {
		if selectedNames.Has(catalogerTask.Name()) {
			result = append(result, catalogerTask)
		}
	}
	return append(result, persistent...), nil
}

func newCatalogerSelectionTask(catalogerTask CatalogerTask) Task {
	return NewTask(catalogerTask.Name(), func(context.Context, file.Resolver, sbomsync.Builder) error {
		return nil
	}, catalogerTask.Tags()...)
}

func cleanCatalogerTaskTags(name string, tags []string) []string {
	set := strset.New(tags...)
	set.Remove("")
	set.Remove(name)
	result := set.List()
	sort.Strings(result)
	return result
}
