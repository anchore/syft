package exp

import (
	"context"
	"fmt"
	"slices"
	"sort"

	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// Task describes a package cataloger before Syft constructs it.
type Task struct {
	catalogerTask task.CatalogerTask
	capabilities  *Capabilities
}

// TaskOption configures a Task.
type TaskOption func(*Task)

// NewCatalogerTask creates a task for an existing package cataloger.
func NewCatalogerTask(cataloger pkg.Cataloger, options ...TaskOption) Task {
	result := Task{catalogerTask: task.NewCatalogerTask(cataloger)}
	for _, option := range options {
		option(&result)
	}
	return result
}

// NewCatalogerTaskFactory creates a task that constructs its cataloger when it runs.
func NewCatalogerTaskFactory(name string, catalogerFactory func() pkg.Cataloger, options ...TaskOption) Task {
	result := Task{catalogerTask: task.NewCatalogerTaskFactory(name, catalogerFactory)}
	for _, option := range options {
		option(&result)
	}
	return result
}

// WithTags adds cataloger selection tags to a task.
func WithTags(tags ...string) TaskOption {
	return func(result *Task) {
		result.catalogerTask = result.catalogerTask.WithTags(tags...)
	}
}

// WithCapabilities adds capability information to a task.
func WithCapabilities(capabilities Capabilities) TaskOption {
	return func(result *Task) {
		capabilities = cloneCapabilities(capabilities)
		result.capabilities = &capabilities
	}
}

// AlwaysEnabled configures a task to ignore cataloger selection.
func AlwaysEnabled() TaskOption {
	return func(result *Task) {
		result.catalogerTask = result.catalogerTask.WithAlwaysEnabled()
	}
}

// Name returns the package cataloger name.
func (t Task) Name() string {
	return t.catalogerTask.Name()
}

// Tags returns the cataloger selection tags.
func (t Task) Tags() []string {
	return t.catalogerTask.Tags()
}

// Capabilities returns a copy of the cataloger's capability information.
func (t Task) Capabilities() (Capabilities, bool) {
	if t.capabilities == nil {
		return Capabilities{}, false
	}

	capabilities := cloneCapabilities(*t.capabilities)
	capabilities.Name = t.Name()
	capabilities.Selectors = t.Tags()
	return capabilities, true
}

// AlwaysEnabled reports whether selection requests can remove the task.
func (t Task) AlwaysEnabled() bool {
	return t.catalogerTask.AlwaysEnabled()
}

// Catalog constructs and runs the package cataloger.
func (t Task) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	return t.catalogerTask.Catalog(ctx, resolver)
}

// SelectCatalogerTasks returns matching tasks without constructing catalogers.
func SelectCatalogerTasks(tasks []Task, selection cataloging.SelectionRequest) ([]Task, error) {
	internalTasks := make(task.CatalogerTasks, 0, len(tasks))
	tasksByName := make(map[string]Task, len(tasks))
	for _, catalogerTask := range tasks {
		internalTasks = append(internalTasks, catalogerTask.catalogerTask)
		tasksByName[catalogerTask.Name()] = catalogerTask
	}

	selectedTasks, err := task.SelectCatalogerTasks(internalTasks, selection)
	if err != nil {
		return nil, err
	}

	result := make([]Task, 0, len(selectedTasks))
	for _, selectedTask := range selectedTasks {
		result = append(result, tasksByName[selectedTask.Name()])
	}
	return result, nil
}

// ListCatalogers returns package cataloger names selected by the configuration.
func ListCatalogers(config *syft.CreateSBOMConfig) ([]string, error) {
	tasks, err := selectedConfigTasks(config)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(tasks))
	for _, catalogerTask := range tasks {
		names = append(names, catalogerTask.Name())
	}
	sort.Strings(names)
	return names, nil
}

// CatalogerInfo returns capability information for package catalogers selected by the configuration.
func CatalogerInfo(config *syft.CreateSBOMConfig) ([]Capabilities, error) {
	tasks, err := selectedConfigTasks(config)
	if err != nil {
		return nil, err
	}

	result := make([]Capabilities, 0, len(tasks))
	for _, catalogerTask := range tasks {
		capabilities, ok := catalogerTask.Capabilities()
		if !ok {
			capabilities = Capabilities{
				Name:      catalogerTask.Name(),
				Type:      "custom",
				Selectors: catalogerTask.Tags(),
			}
		}
		result = append(result, capabilities)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result, nil
}

func selectedConfigTasks(config *syft.CreateSBOMConfig) ([]Task, error) {
	if config == nil {
		return nil, fmt.Errorf("create SBOM config is nil")
	}

	internalTasks, err := config.CatalogerTasks()
	if err != nil {
		return nil, err
	}
	selectedTasks, err := task.SelectCatalogerTasks(internalTasks, config.CatalogerSelectionRequest())
	if err != nil {
		return nil, err
	}
	return wrapCatalogerTasks(selectedTasks)
}

func wrapCatalogerTasks(tasks task.CatalogerTasks) ([]Task, error) {
	capabilitiesByName, err := packageCatalogerCapabilitiesByName()
	if err != nil {
		return nil, err
	}

	result := make([]Task, 0, len(tasks))
	for _, catalogerTask := range tasks {
		wrapped := Task{catalogerTask: catalogerTask}
		if capabilities, ok := capabilitiesByName[catalogerTask.Name()]; ok {
			capabilities := cloneCapabilities(capabilities)
			wrapped.capabilities = &capabilities
		}
		result = append(result, wrapped)
	}
	return result, nil
}

func packageCatalogerCapabilitiesByName() (map[string]Capabilities, error) {
	allCapabilities, err := PackageCatalogerCapabilities()
	if err != nil {
		return nil, err
	}

	result := make(map[string]Capabilities, len(allCapabilities))
	for _, capabilities := range allCapabilities {
		result[capabilities.Name] = capabilities
	}
	return result, nil
}

func cloneCapabilities(capabilities Capabilities) Capabilities {
	return Capabilities{
		Ecosystem:       capabilities.Ecosystem,
		Name:            capabilities.Name,
		Type:            capabilities.Type,
		Source:          capabilities.Source,
		Config:          capabilities.Config,
		Selectors:       slices.Clone(capabilities.Selectors),
		Parsers:         convert(capabilities.Parsers, cloneParser),
		Detectors:       convert(capabilities.Detectors, cloneDetector),
		MetadataTypes:   slices.Clone(capabilities.MetadataTypes),
		PackageTypes:    slices.Clone(capabilities.PackageTypes),
		PURLTypes:       slices.Clone(capabilities.PURLTypes),
		JSONSchemaTypes: slices.Clone(capabilities.JSONSchemaTypes),
		Capabilities:    CapabilitySet(convert(capabilities.Capabilities, cloneCapabilityField)),
	}
}

func cloneParser(parser Parser) Parser {
	return Parser{
		ParserFunction:  parser.ParserFunction,
		Detector:        cloneDetector(parser.Detector),
		MetadataTypes:   slices.Clone(parser.MetadataTypes),
		PackageTypes:    slices.Clone(parser.PackageTypes),
		PURLTypes:       slices.Clone(parser.PURLTypes),
		JSONSchemaTypes: slices.Clone(parser.JSONSchemaTypes),
		Capabilities:    CapabilitySet(convert(parser.Capabilities, cloneCapabilityField)),
	}
}

func cloneDetector(detector Detector) Detector {
	return Detector{
		Method:     detector.Method,
		Criteria:   slices.Clone(detector.Criteria),
		Conditions: convert(detector.Conditions, cloneDetectorCondition),
		Packages:   convert(detector.Packages, cloneDetectorPackageInfo),
		Comment:    detector.Comment,
	}
}

func cloneDetectorCondition(condition DetectorCondition) DetectorCondition {
	return DetectorCondition{
		When:    cloneMap(condition.When),
		Comment: condition.Comment,
	}
}

func cloneDetectorPackageInfo(packageInfo DetectorPackageInfo) DetectorPackageInfo {
	return DetectorPackageInfo{
		Class: packageInfo.Class,
		Name:  packageInfo.Name,
		PURL:  packageInfo.PURL,
		CPEs:  slices.Clone(packageInfo.CPEs),
		Type:  packageInfo.Type,
	}
}

func cloneCapabilityField(field CapabilityField) CapabilityField {
	return CapabilityField{
		Name:       field.Name,
		Default:    cloneValue(field.Default),
		Conditions: convert(field.Conditions, cloneCapabilityCondition),
		Evidence:   slices.Clone(field.Evidence),
		Comment:    field.Comment,
	}
}

func cloneCapabilityCondition(condition CapabilityCondition) CapabilityCondition {
	return CapabilityCondition{
		When:    cloneMap(condition.When),
		Value:   cloneValue(condition.Value),
		Comment: condition.Comment,
	}
}
