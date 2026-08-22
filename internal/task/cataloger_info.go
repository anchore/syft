package task

import (
	"sort"

	"github.com/scylladb/go-set/strset"
)

// CatalogerInfo is a cataloger's name and the selection tags that match it.
type CatalogerInfo struct {
	Name      string
	Selectors []string
}

// ExtractCatalogerInfo extracts cataloger names and their selection tags from tasks
func ExtractCatalogerInfo(tasks []Task) []CatalogerInfo {
	var infos []CatalogerInfo

	for _, tsk := range tasks {
		var selectors []string
		name := tsk.Name()

		if s, ok := tsk.(Selector); ok {
			set := strset.New(s.Selectors()...)
			set.Remove(name)
			selectors = set.List()
			sort.Strings(selectors)
		}

		infos = append(infos, CatalogerInfo{
			Name:      name,
			Selectors: selectors,
		})
	}

	return infos
}
