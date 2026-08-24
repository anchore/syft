package task

import (
	"fmt"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"
)

type Factory interface {
	Name() string
	Selectors() []string
	Task(CatalogingFactoryConfig) Task
}

type factory struct {
	name        string
	tags        []string
	taskFactory func(CatalogingFactoryConfig) Task
}

type Factories []Factory

func newTaskFactory(name string, taskFactory func(CatalogingFactoryConfig) Task, tags ...string) factory {
	return factory{
		name:        name,
		tags:        tags,
		taskFactory: taskFactory,
	}
}

func (f factory) Name() string {
	return f.name
}

func (f factory) Selectors() []string {
	return selectors(f.name, f.tags...)
}

func (f factory) Task(cfg CatalogingFactoryConfig) Task {
	if f.taskFactory == nil {
		return nil
	}
	return f.taskFactory(cfg)
}

func (f Factories) Tasks(cfg CatalogingFactoryConfig) ([]Task, error) {
	var allTasks []Task
	taskNames := strset.New()
	duplicateTaskNames := strset.New()
	var err error
	for _, fact := range f {
		tsk := fact.Task(cfg)
		if tsk == nil {
			continue
		}
		tskName := tsk.Name()
		if taskNames.Has(tskName) {
			duplicateTaskNames.Add(tskName)
		}

		allTasks = append(allTasks, tsk)
		taskNames.Add(tskName)
	}
	if duplicateTaskNames.Size() > 0 {
		names := duplicateTaskNames.List()
		sort.Strings(names)
		err = fmt.Errorf("duplicate cataloger task names: %v", strings.Join(names, ", "))
	}

	return allTasks, err
}

func selectors(name string, tags ...string) []string {
	set := strset.New(tags...)
	set.Add(name)
	list := set.List()
	sort.Strings(list)
	return list
}
