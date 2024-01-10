package task

import (
	"context"
	"fmt"
	"sort"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/file"
)

var _ interface {
	Task
	Selector
} = (*task)(nil)

// Task is a function that can wrap a cataloger to populate the SBOM with data (coordinated through the mutex).
type Task interface {
	Name() string
	Execute(context.Context, file.Resolver, sbomsync.Builder) error
}

type Selector interface {
	HasAllSelectors(...string) bool
	Selectors() []string
}

type tasks []Task

type task struct {
	name      string
	selectors *strset.Set
	task      func(context.Context, file.Resolver, sbomsync.Builder) error
}

func NewTask(name string, tsk func(context.Context, file.Resolver, sbomsync.Builder) error, tags ...string) Task {
	if tsk == nil {
		panic(fmt.Errorf("task cannot be nil"))
	}
	tags = append(tags, name)
	return &task{
		name:      name,
		selectors: strset.New(tags...),
		task:      tsk,
	}
}

func (t task) HasAllSelectors(ids ...string) bool {
	// tags or name
	return t.selectors.Has(ids...)
}

func (t task) Selectors() []string {
	return t.selectors.List()
}

func (t task) Name() string {
	return t.name
}

func (t task) Execute(ctx context.Context, resolver file.Resolver, sbom sbomsync.Builder) error {
	return t.task(ctx, resolver, sbom)
}

func (ts tasks) Names() []string {
	var names []string
	for _, td := range ts {
		names = append(names, td.Name())
	}
	return names
}

func (ts tasks) Tags() []string {
	tags := strset.New()
	for _, td := range ts {
		if s, ok := td.(Selector); ok {
			tags.Add(s.Selectors()...)
		}

		tags.Remove(td.Name())
	}

	tagsList := tags.List()
	sort.Strings(tagsList)

	return tagsList
}
