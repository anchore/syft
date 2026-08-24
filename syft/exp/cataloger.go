package exp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/capabilities"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	_ "github.com/anchore/syft/syft/pkg/cataloger"
)

// Cataloger describes an available package cataloger and its selection metadata.
type Cataloger struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

// Task describes a package cataloger that can be selected and inspected before the cataloger is constructed.
type Task struct {
	name             string
	tags             []string
	capabilities     *Capabilities
	catalogerFactory func() pkg.Cataloger
	alwaysEnabled    bool
}

type TaskOption func(*Task)

// CatalogerTaskProvider is implemented by configuration types that can provide experimental cataloger tasks.
type CatalogerTaskProvider interface {
	CatalogerTasks() ([]Task, error)
	CatalogerSelectionRequest() cataloging.SelectionRequest
}

// NewCatalogerTask creates a task from an already-constructed package cataloger.
func NewCatalogerTask(cataloger pkg.Cataloger, options ...TaskOption) Task {
	if cataloger == nil {
		return Task{}
	}
	return NewCatalogerTaskFactory(cataloger.Name(), func() pkg.Cataloger {
		return cataloger
	}, options...)
}

// NewCatalogerTaskFactory creates a task that constructs its package cataloger only when needed.
func NewCatalogerTaskFactory(name string, catalogerFactory func() pkg.Cataloger, options ...TaskOption) Task {
	t := Task{
		name:             name,
		catalogerFactory: catalogerFactory,
	}
	WithTags(pkgcataloging.PackageTag)(&t)
	for _, opt := range options {
		opt(&t)
	}
	return t
}

func WithTags(tags ...string) TaskOption {
	return func(t *Task) {
		t.tags = append(t.tags, tags...)
		t.tags = cleanTags(t.name, t.tags)
	}
}

func WithCapabilities(c Capabilities) TaskOption {
	return func(t *Task) {
		if c.Name == "" {
			c.Name = t.name
		}
		c.Selectors = cleanTags(t.name, append(c.Selectors, t.tags...))
		t.capabilities = &c
	}
}

func AlwaysEnabled() TaskOption {
	return func(t *Task) {
		t.alwaysEnabled = true
	}
}

func (t Task) Name() string {
	return t.name
}

func (t Task) Tags() []string {
	return append([]string(nil), t.tags...)
}

func (t Task) Capabilities() (Capabilities, bool) {
	if t.capabilities == nil {
		return Capabilities{}, false
	}
	c := *t.capabilities
	c.Name = t.name
	c.Selectors = cleanTags(t.name, append(c.Selectors, t.tags...))
	return c, true
}

func (t Task) Cataloger() pkg.Cataloger {
	if t.catalogerFactory == nil {
		return nil
	}
	return t.catalogerFactory()
}

func (t Task) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	cataloger := t.Cataloger()
	if cataloger == nil {
		return nil, nil, fmt.Errorf("cataloger task %q has no cataloger factory", t.name)
	}
	return cataloger.Catalog(ctx, resolver)
}

func (t Task) AlwaysEnabled() bool {
	return t.alwaysEnabled
}

func newCatalogerTasks(factories task.Factories, cfg task.CatalogingFactoryConfig, refs ...pkgcataloging.CatalogerReference) ([]Task, error) {
	capabilitiesByName, err := catalogerCapabilitiesByName()
	if err != nil {
		return nil, err
	}

	var tasks []Task
	for _, factory := range factories {
		packageFactory, ok := factory.(task.PackageFactory)
		if !ok {
			continue
		}

		name := packageFactory.Name()
		pf := packageFactory
		catalogerTask := NewCatalogerTaskFactory(name, func() pkg.Cataloger {
			return pf.Cataloger(cfg)
		}, WithTags(tagsWithoutName(name, packageFactory.Selectors())...))

		if c, ok := capabilitiesByName[name]; ok {
			catalogerTask.capabilities = &c
		}
		tasks = append(tasks, catalogerTask)
	}

	for _, ref := range refs {
		if ref.Cataloger == nil {
			return nil, fmt.Errorf("provided cataloger reference without a cataloger")
		}

		options := []TaskOption{WithTags(ref.Tags...)}
		if ref.AlwaysEnabled {
			options = append(options, AlwaysEnabled())
		}
		tasks = append(tasks, NewCatalogerTask(ref.Cataloger, options...))
	}

	if err := validateTaskNames(tasks); err != nil {
		return nil, err
	}

	return tasks, nil
}

// ListCatalogers returns the names of package catalogers selected by the provider's selection request.
func ListCatalogers(provider CatalogerTaskProvider) ([]string, error) {
	tasks, err := selectedProviderTasks(provider)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(tasks))
	for _, t := range tasks {
		names = append(names, t.Name())
	}
	sort.Strings(names)
	return names, nil
}

// CatalogerInfo returns package cataloger capabilities selected by the provider's selection request.
func CatalogerInfo(provider CatalogerTaskProvider) ([]Capabilities, error) {
	tasks, err := selectedProviderTasks(provider)
	if err != nil {
		return nil, err
	}

	result := make([]Capabilities, 0, len(tasks))
	for _, t := range tasks {
		if c, ok := t.Capabilities(); ok {
			result = append(result, c)
			continue
		}
		result = append(result, Capabilities{
			Name:      t.Name(),
			Type:      "custom",
			Selectors: t.Tags(),
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result, nil
}

// PackageCatalogerCapabilities returns all embedded package cataloger capabilities.
func PackageCatalogerCapabilities() ([]Capabilities, error) {
	entries, err := capabilities.Packages()
	if err != nil {
		return nil, err
	}

	result := make([]Capabilities, 0, len(entries))
	for _, entry := range entries {
		converted, err := convertCapabilities(entry)
		if err != nil {
			return nil, err
		}
		result = append(result, converted)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result, nil
}

// SelectCatalogerTasks returns tasks matching a selection request without constructing catalogers.
func SelectCatalogerTasks(tasks []Task, selection cataloging.SelectionRequest) ([]Task, error) {
	if selection.IsEmpty() {
		return append([]Task(nil), tasks...), nil
	}

	var selectable []Task
	var persistent []Task
	for _, t := range tasks {
		if t.AlwaysEnabled() {
			persistent = append(persistent, t)
			continue
		}
		selectable = append(selectable, t)
	}

	selectionTasks := make([]task.Task, 0, len(selectable))
	for _, t := range selectable {
		selectionTasks = append(selectionTasks, selectionTask(t))
	}

	selectedSelectionTasks, _, err := task.Select(selectionTasks, selection)
	if err != nil {
		return nil, fmt.Errorf("unable to select catalogers: %w", err)
	}

	selectedNames := strset.New()
	for _, selected := range selectedSelectionTasks {
		selectedNames.Add(selected.Name())
	}

	var selected []Task
	for _, t := range selectable {
		if selectedNames.Has(t.Name()) {
			selected = append(selected, t)
		}
	}
	selected = append(selected, persistent...)

	return selected, nil
}

// AllCatalogers returns information about all registered package catalogers, sorted by name.
func AllCatalogers(additional ...pkgcataloging.CatalogerReference) ([]Cataloger, error) {
	return SelectCatalogers(cataloging.NewSelectionRequest().WithDefaults("all"), additional...)
}

// SelectCatalogers returns information about package catalogers matching the given selection request.
func SelectCatalogers(selection cataloging.SelectionRequest, additional ...pkgcataloging.CatalogerReference) ([]Cataloger, error) {
	tasks, err := newCatalogerTasks(task.DefaultPackageTaskFactories(), task.DefaultCatalogingFactoryConfig(), additional...)
	if err != nil {
		return nil, err
	}
	selected, err := SelectCatalogerTasks(tasks, selection)
	if err != nil {
		return nil, err
	}
	return extractCatalogers(selected), nil
}

func selectedProviderTasks(provider CatalogerTaskProvider) ([]Task, error) {
	if provider == nil {
		return nil, fmt.Errorf("cataloger task provider is nil")
	}
	tasks, err := provider.CatalogerTasks()
	if err != nil {
		return nil, err
	}
	return SelectCatalogerTasks(tasks, provider.CatalogerSelectionRequest())
}

func selectionTask(t Task) task.Task {
	return task.NewTask(t.Name(), func(context.Context, file.Resolver, sbomsync.Builder) error {
		return nil
	}, t.Tags()...)
}

func extractCatalogers(tasks []Task) []Cataloger {
	catalogers := make([]Cataloger, 0, len(tasks))
	for _, t := range tasks {
		catalogers = append(catalogers, Cataloger{
			Name: t.Name(),
			Tags: t.Tags(),
		})
	}

	sort.Slice(catalogers, func(i, j int) bool {
		return catalogers[i].Name < catalogers[j].Name
	})

	return catalogers
}

func tagsWithoutName(name string, selectors []string) []string {
	var tags []string
	for _, selector := range selectors {
		if selector == name {
			continue
		}
		tags = append(tags, selector)
	}
	return cleanTags(name, tags)
}

func cleanTags(name string, tags []string) []string {
	set := strset.New(tags...)
	set.Remove("")
	set.Remove(name)
	result := set.List()
	sort.Strings(result)
	return result
}

func validateTaskNames(tasks []Task) error {
	seen := strset.New()
	duplicates := strset.New()
	for _, t := range tasks {
		if t.Name() == "" {
			return fmt.Errorf("cataloger task without a name")
		}
		if seen.Has(t.Name()) {
			duplicates.Add(t.Name())
		}
		seen.Add(t.Name())
	}
	if duplicates.Size() == 0 {
		return nil
	}
	names := duplicates.List()
	sort.Strings(names)
	return fmt.Errorf("duplicate cataloger task names: %v", names)
}

func catalogerCapabilitiesByName() (map[string]Capabilities, error) {
	entries, err := PackageCatalogerCapabilities()
	if err != nil {
		return nil, err
	}

	result := make(map[string]Capabilities, len(entries))
	for _, entry := range entries {
		result[entry.Name] = entry
	}
	return result, nil
}

func convertCapabilities(value any) (Capabilities, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return Capabilities{}, fmt.Errorf("unable to marshal cataloger capabilities: %w", err)
	}
	var result Capabilities
	if err := json.Unmarshal(data, &result); err != nil {
		return Capabilities{}, fmt.Errorf("unable to unmarshal cataloger capabilities: %w", err)
	}
	return result, nil
}
