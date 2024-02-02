package syft

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/filecataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// CreateSBOMConfig specifies all parameters needed for creating an SBOM.
type CreateSBOMConfig struct {
	// required configuration input to specify how cataloging should be performed
	Search             cataloging.SearchConfig
	Relationships      cataloging.RelationshipsConfig
	DataGeneration     cataloging.DataGenerationConfig
	Packages           pkgcataloging.Config
	Files              filecataloging.Config
	Parallelism        int
	CatalogerSelection pkgcataloging.SelectionRequest

	// audit what tool is being used to generate the SBOM
	ToolName          string
	ToolVersion       string
	ToolConfiguration interface{}

	packageTaskFactories       task.PackageTaskFactories
	packageCatalogerReferences []pkgcataloging.CatalogerReference
}

func DefaultCreateSBOMConfig() *CreateSBOMConfig {
	return &CreateSBOMConfig{
		Search:               cataloging.DefaultSearchConfig(),
		Relationships:        cataloging.DefaultRelationshipsConfig(),
		DataGeneration:       cataloging.DefaultDataGenerationConfig(),
		Packages:             pkgcataloging.DefaultConfig(),
		Files:                filecataloging.DefaultConfig(),
		Parallelism:          1,
		packageTaskFactories: task.DefaultPackageTaskFactories(),
	}
}

// WithTool allows for setting the specific name, version, and any additional configuration that is not captured
// in the syft default API configuration. This could cover inputs for catalogers that were user-provided, thus,
// is not visible to the syft API, but would be useful to see in the SBOM output.
func (c *CreateSBOMConfig) WithTool(name, version string, cfg ...any) *CreateSBOMConfig {
	c.ToolName = name
	c.ToolVersion = version
	c.ToolConfiguration = cfg
	return c
}

// WithParallelism allows for setting the number of concurrent cataloging tasks that can be performed at once
func (c *CreateSBOMConfig) WithParallelism(p int) *CreateSBOMConfig {
	if p < 1 {
		// TODO: warn?
		p = 1
	}
	c.Parallelism = p
	return c
}

// WithSearchConfig allows for setting the specific search configuration for cataloging.
func (c *CreateSBOMConfig) WithSearchConfig(cfg cataloging.SearchConfig) *CreateSBOMConfig {
	c.Search = cfg
	return c
}

// WithRelationshipsConfig allows for defining the specific relationships that should be captured during cataloging.
func (c *CreateSBOMConfig) WithRelationshipsConfig(cfg cataloging.RelationshipsConfig) *CreateSBOMConfig {
	c.Relationships = cfg
	return c
}

// WithDataGenerationConfig allows for defining what data elements that cannot be discovered from the underlying
// target being scanned that should be generated after package creation.
func (c *CreateSBOMConfig) WithDataGenerationConfig(cfg cataloging.DataGenerationConfig) *CreateSBOMConfig {
	c.DataGeneration = cfg
	return c
}

// WithPackagesConfig allows for defining any specific behavior for syft-implemented catalogers.
func (c *CreateSBOMConfig) WithPackagesConfig(cfg pkgcataloging.Config) *CreateSBOMConfig {
	c.Packages = cfg
	return c
}

// WithFilesConfig allows for defining file-based cataloging parameters.
func (c *CreateSBOMConfig) WithFilesConfig(cfg filecataloging.Config) *CreateSBOMConfig {
	c.Files = cfg
	return c
}

// WithoutFiles allows for disabling file cataloging altogether.
func (c *CreateSBOMConfig) WithoutFiles() *CreateSBOMConfig {
	c.Files = filecataloging.Config{
		Selection: file.NoFilesSelection,
		Hashers:   nil,
	}
	return c
}

// WithCatalogerSelection allows for adding to, removing from, or sub-selecting the final set of catalogers by name or tag.
func (c *CreateSBOMConfig) WithCatalogerSelection(selection pkgcataloging.SelectionRequest) *CreateSBOMConfig {
	c.CatalogerSelection = selection
	return c
}

// WithoutCatalogers removes all catalogers from the final set of catalogers. This is useful if you want to only use
// user-provided catalogers (without the default syft-provided catalogers).
func (c *CreateSBOMConfig) WithoutCatalogers() *CreateSBOMConfig {
	c.packageTaskFactories = nil
	c.packageCatalogerReferences = nil
	return c
}

// WithCatalogers allows for adding user-provided catalogers to the final set of catalogers that will always be run
// regardless of the source type or any cataloger selections provided.
func (c *CreateSBOMConfig) WithCatalogers(catalogerRefs ...pkgcataloging.CatalogerReference) *CreateSBOMConfig {
	c.packageCatalogerReferences = append(c.packageCatalogerReferences, catalogerRefs...)

	return c
}

// makeTaskGroups considers the entire configuration and finalizes the set of tasks to be run. Tasks are run in
// groups, where each task in a group can be run concurrently, while tasks in different groups must be run serially.
// The final set of task groups is returned along with a cataloger manifest that describes the catalogers that were
// selected and the tokens that were sensitive to this selection (both for adding and removing from the final set).
func (c *CreateSBOMConfig) makeTaskGroups(src source.Description) ([][]task.Task, *catalogerManifest, error) {
	var taskGroups [][]task.Task

	// generate package and file tasks based on the configuration
	environmentTasks := c.environmentTasks()
	relationshipsTasks := c.relationshipTasks(src)
	fileTasks := c.fileTasks()
	pkgTasks, selectionEvidence, err := c.packageTasks(src)
	if err != nil {
		return nil, nil, err
	}

	// combine the user-provided and configured tasks
	if c.Files.Selection == file.FilesOwnedByPackageSelection {
		// special case: we need the package info when we are cataloging files owned by packages
		taskGroups = append(taskGroups, pkgTasks, fileTasks)
	} else {
		taskGroups = append(taskGroups, append(pkgTasks, fileTasks...))
	}

	// all relationship work must be done after all nodes (files and packages) have been cataloged
	if len(relationshipsTasks) > 0 {
		taskGroups = append(taskGroups, relationshipsTasks)
	}

	// identifying the environment (i.e. the linux release) must be done first as this is required for package cataloging
	taskGroups = append(
		[][]task.Task{
			environmentTasks,
		},
		taskGroups...,
	)

	return taskGroups, &catalogerManifest{
		Requested: selectionEvidence.Request,
		Used:      formatTaskNames(pkgTasks),
	}, nil
}

// fileTasks returns the set of tasks that should be run to catalog files.
func (c *CreateSBOMConfig) fileTasks() []task.Task {
	var tsks []task.Task

	if t := task.NewFileDigestCatalogerTask(c.Files.Selection, c.Files.Hashers...); t != nil {
		tsks = append(tsks, t)
	}
	if t := task.NewFileMetadataCatalogerTask(c.Files.Selection); t != nil {
		tsks = append(tsks, t)
	}
	if t := task.NewFileContentCatalogerTask(c.Files.Content); t != nil {
		tsks = append(tsks, t)
	}
	if t := task.NewExecutableCatalogerTask(c.Files.Selection, c.Files.Executable); t != nil {
		tsks = append(tsks, t)
	}

	return tsks
}

// packageTasks returns the set of tasks that should be run to catalog packages.
func (c *CreateSBOMConfig) packageTasks(src source.Description) ([]task.Task, *task.Selection, error) {
	cfg := task.CatalogingFactoryConfig{
		SearchConfig:         c.Search,
		RelationshipsConfig:  c.Relationships,
		DataGenerationConfig: c.DataGeneration,
		PackagesConfig:       c.Packages,
	}

	persistentTasks, selectableTasks, err := c.allPackageTasks(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create package cataloger tasks: %w", err)
	}

	req, err := finalSelectionRequest(c.CatalogerSelection, src)
	if err != nil {
		return nil, nil, err
	}

	finalTasks, selection, err := task.Select(selectableTasks, *req)
	if err != nil {
		return nil, nil, err
	}

	finalTasks = append(finalTasks, persistentTasks...)

	if len(finalTasks) == 0 {
		return nil, nil, fmt.Errorf("no catalogers selected")
	}

	return finalTasks, &selection, nil
}

func finalSelectionRequest(req pkgcataloging.SelectionRequest, src source.Description) (*pkgcataloging.SelectionRequest, error) {
	if len(req.DefaultNamesOrTags) == 0 {
		defaultTag, err := findDefaultTag(src)
		if err != nil {
			return nil, fmt.Errorf("unable to determine default cataloger tag: %w", err)
		}

		if defaultTag != "" {
			req.DefaultNamesOrTags = append(req.DefaultNamesOrTags, defaultTag)
		}

		req.RemoveNamesOrTags = replaceDefaultTagReferences(defaultTag, req.RemoveNamesOrTags)
		req.SubSelectTags = replaceDefaultTagReferences(defaultTag, req.SubSelectTags)
	}

	return &req, nil
}

func (c *CreateSBOMConfig) allPackageTasks(cfg task.CatalogingFactoryConfig) ([]task.Task, []task.Task, error) {
	persistentPackageTasks, selectablePackageTasks, err := c.userPackageTasks(cfg)
	if err != nil {
		return nil, nil, err
	}

	tsks, err := c.packageTaskFactories.Tasks(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create package cataloger tasks: %w", err)
	}

	return persistentPackageTasks, append(tsks, selectablePackageTasks...), nil
}

func (c *CreateSBOMConfig) userPackageTasks(cfg task.CatalogingFactoryConfig) ([]task.Task, []task.Task, error) {
	var (
		persistentPackageTasks []task.Task
		selectablePackageTasks []task.Task
	)

	for _, catalogerRef := range c.packageCatalogerReferences {
		if catalogerRef.Cataloger == nil {
			return nil, nil, errors.New("provided cataloger reference without a cataloger")
		}
		if catalogerRef.AlwaysEnabled {
			persistentPackageTasks = append(persistentPackageTasks, task.NewPackageTask(cfg, catalogerRef.Cataloger, catalogerRef.Tags...))
			continue
		}
		if len(catalogerRef.Tags) == 0 {
			return nil, nil, errors.New("provided cataloger reference without tags")
		}
		selectablePackageTasks = append(selectablePackageTasks, task.NewPackageTask(cfg, catalogerRef.Cataloger, catalogerRef.Tags...))
	}

	return persistentPackageTasks, selectablePackageTasks, nil
}

// relationshipTasks returns the set of tasks that should be run to generate additional relationships as well as
// prune existing relationships.
func (c *CreateSBOMConfig) relationshipTasks(src source.Description) []task.Task {
	var tsks []task.Task

	if t := task.NewRelationshipsTask(c.Relationships, src); t != nil {
		tsks = append(tsks, t)
	}
	return tsks
}

// environmentTasks returns the set of tasks that should be run to identify what is being scanned or the context
// of where it is being scanned. Today this is used to identify the linux distribution release for container images
// being scanned.
func (c *CreateSBOMConfig) environmentTasks() []task.Task {
	var tsks []task.Task

	if t := task.NewEnvironmentTask(); t != nil {
		tsks = append(tsks, t)
	}
	return tsks
}

func (c *CreateSBOMConfig) validate() error {
	if c.Relationships.ExcludeBinaryPackagesWithFileOwnershipOverlap {
		if !c.Relationships.PackageFileOwnershipOverlap {
			return fmt.Errorf("invalid configuration: to exclude binary packages based on file ownership overlap relationships, cataloging file ownership overlap relationships must be enabled")
		}
	}
	return nil
}

// Create creates an SBOM from the given source with the current SBOM configuration.
func (c *CreateSBOMConfig) Create(ctx context.Context, src source.Source) (*sbom.SBOM, error) {
	return CreateSBOM(ctx, src, c)
}

func findDefaultTag(src source.Description) (string, error) {
	switch m := src.Metadata.(type) {
	case source.StereoscopeImageSourceMetadata:
		return pkgcataloging.ImageTag, nil
	case source.FileSourceMetadata, source.DirectorySourceMetadata:
		return pkgcataloging.DirectoryTag, nil
	default:
		return "", fmt.Errorf("unable to determine default cataloger tag for source type=%T", m)
	}
}

func replaceDefaultTagReferences(defaultTag string, lst []string) []string {
	for i, tag := range lst {
		if strings.ToLower(tag) == "default" {
			lst[i] = defaultTag
		}
	}
	return lst
}
