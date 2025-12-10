package task

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"
)

type factory func(cfg CatalogingFactoryConfig) (Task, error)

type Factories []factory

func (f Factories) Tasks(cfg CatalogingFactoryConfig) ([]Task, error) {
	var allTasks []Task
	taskNames := strset.New()
	duplicateTaskNames := strset.New()
	var errs []error
	for _, fact := range f {
		tsk, err := fact(cfg)
		if err != nil {
			errs = append(errs, err)
			continue
		}
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
		errs = append(errs, fmt.Errorf("duplicate cataloger task names: %v", strings.Join(names, ", ")))
	}

	return allTasks, errors.Join(errs...)
}
