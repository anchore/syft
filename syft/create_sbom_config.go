package syft

import (
	"fmt"
	"strings"

	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/filecataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
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

	packageTaskFactories           task.PackageTaskFactories // syft default + user-provided catalogers with tags to select with
	persistentPackageTaskFactories task.PackageTaskFactories // user-provided catalogers without tags to select with
}

func DefaultCreateSBOMConfig() CreateSBOMConfig {
	return CreateSBOMConfig{
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
func (c CreateSBOMConfig) WithTool(name, version string, cfg ...any) CreateSBOMConfig {
	c.ToolName = name
	c.ToolVersion = version
	c.ToolConfiguration = cfg
	return c
}

// WithParallelism allows for setting the number of concurrent cataloging tasks that can be performed at once
func (c CreateSBOMConfig) WithParallelism(p int) CreateSBOMConfig {
	if p < 1 {
		// TODO: warn?
		p = 1
	}
	c.Parallelism = p
	return c
}

// WithSearchConfig allows for setting the specific search configuration for cataloging.
func (c CreateSBOMConfig) WithSearchConfig(cfg cataloging.SearchConfig) CreateSBOMConfig {
	c.Search = cfg
	return c
}

// WithRelationshipsConfig allows for defining the specific relationships that should be captured during cataloging.
func (c CreateSBOMConfig) WithRelationshipsConfig(cfg cataloging.RelationshipsConfig) CreateSBOMConfig {
	c.Relationships = cfg
	return c
}

// WithDataGenerationConfig allows for defining what data elements that cannot be discovered from the underlying
// target being scanned that should be generated after package creation.
func (c CreateSBOMConfig) WithDataGenerationConfig(cfg cataloging.DataGenerationConfig) CreateSBOMConfig {
	c.DataGeneration = cfg
	return c
}

// WithPackagesConfig allows for defining any specific behavior for syft-implemented catalogers.
func (c CreateSBOMConfig) WithPackagesConfig(cfg pkgcataloging.Config) CreateSBOMConfig {
	c.Packages = cfg
	return c
}

// WithFilesConfig allows for defining file-based cataloging parameters.
func (c CreateSBOMConfig) WithFilesConfig(cfg filecataloging.Config) CreateSBOMConfig {
	c.Files = cfg
	return c
}

// WithoutFiles allows for disabling file cataloging altogether.
func (c CreateSBOMConfig) WithoutFiles() CreateSBOMConfig {
	c.Files = filecataloging.Config{
		Selection: file.NoFilesSelection,
		Hashers:   nil,
	}
	return c
}

// WithCatalogerSelection allows for adding to, removing from, or sub-selecting the final set of catalogers by name or tag.
func (c CreateSBOMConfig) WithCatalogerSelection(selection pkgcataloging.SelectionRequest) CreateSBOMConfig {
	c.CatalogerSelection = selection
	return c
}

// WithoutCatalogers removes all catalogers from the final set of catalogers. This is useful if you want to only use
// user-provided catalogers (without the default syft-provided catalogers).
func (c CreateSBOMConfig) WithoutCatalogers() CreateSBOMConfig {
	c.packageTaskFactories = nil
	c.persistentPackageTaskFactories = nil
	return c
}

// WithCatalogers allows for adding user-provided catalogers to the final set of catalogers that will always be run
// regardless of the source type or any cataloger selections provided.
func (c CreateSBOMConfig) WithCatalogers(catalogers ...pkg.Cataloger) CreateSBOMConfig {
	for _, cat := range catalogers {
		c.persistentPackageTaskFactories = append(c.persistentPackageTaskFactories,
			func(cfg task.CatalogingFactoryConfig) task.Task {
				return task.NewPackageTask(cfg, cat)
			},
		)
	}

	return c
}

// WithCataloger allows for adding a user-provided cataloger to the final set of catalogers that will conditionally
// be run based on the tags provided, the source type, and the user-provided cataloger selections. For example, if you
// would like the given cataloger to be run against container images, minimally provide the "image" tag. If you would
// like the given cataloger to be run against file systems, minimally provide the "directory" tag. Providing no tags
// means that the cataloger will always be included in the final cataloger selection.
func (c CreateSBOMConfig) WithCataloger(cat pkg.Cataloger, tags ...string) CreateSBOMConfig {
	if len(tags) == 0 {
		return c.WithCatalogers(cat)
	}

	c.packageTaskFactories = append(c.packageTaskFactories,
		func(cfg task.CatalogingFactoryConfig) task.Task {
			return task.NewPackageTask(cfg, cat, tags...)
		},
	)

	return c
}

// makeTaskGroups considers the entire configuration and finalizes the set of tasks to be run. Tasks are run in
// groups, where each task in a group can be run concurrently, while tasks in different groups must be run serially.
// The final set of task groups is returned along with a cataloger manifest that describes the catalogers that were
// selected and the tokens that were sensitive to this selection (both for adding and removing from the final set).
func (c CreateSBOMConfig) makeTaskGroups(src source.Description) ([][]task.Task, *catalogerManifest, error) {
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
	if c.Files.Selection == file.OwnedFilesSelection {
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
func (c CreateSBOMConfig) fileTasks() []task.Task {
	var tsks []task.Task

	if t := task.NewFileDigestCatalogerTask(c.Files.Selection, c.Files.Hashers...); t != nil {
		tsks = append(tsks, t)
	}
	if t := task.NewFileMetadataCatalogerTask(c.Files.Selection); t != nil {
		tsks = append(tsks, t)
	}
	return tsks
}

// packageTasks returns the set of tasks that should be run to catalog packages.
func (c CreateSBOMConfig) packageTasks(src source.Description) ([]task.Task, *task.Selection, error) {
	cfg := task.CatalogingFactoryConfig{
		SearchConfig:         c.Search,
		RelationshipsConfig:  c.Relationships,
		DataGenerationConfig: c.DataGeneration,
		PackagesConfig:       c.Packages,
	}
	tsks, err := c.packageTaskFactories.Tasks(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create package cataloger tasks: %w", err)
	}

	if len(c.CatalogerSelection.DefaultNamesOrTags) == 0 {
		defaultTag, err := findDefaultTag(src)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to determine default cataloger tag: %w", err)
		}

		if defaultTag != "" {
			c.CatalogerSelection.DefaultNamesOrTags = append(c.CatalogerSelection.DefaultNamesOrTags, defaultTag)
		}

		c.CatalogerSelection.RemoveNamesOrTags = replaceDefaultTagReferences(defaultTag, c.CatalogerSelection.RemoveNamesOrTags)
		c.CatalogerSelection.SubSelectTags = replaceDefaultTagReferences(defaultTag, c.CatalogerSelection.SubSelectTags)
	}

	finalTasks, selection, err := task.Select(tsks, c.CatalogerSelection)
	if err != nil {
		return nil, nil, err
	}

	pTsks, err := c.persistentPackageTaskFactories.Tasks(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create persistent package cataloger tasks: %w", err)
	}
	finalTasks = append(finalTasks, pTsks...)

	if len(finalTasks) == 0 {
		return nil, nil, fmt.Errorf("no catalogers selected")
	}

	return finalTasks, &selection, nil
}

// relationshipTasks returns the set of tasks that should be run to generate additional relationships as well as
// prune existing relationships.
func (c CreateSBOMConfig) relationshipTasks(src source.Description) []task.Task {
	var tsks []task.Task

	if t := task.NewRelationshipsTask(c.Relationships, src); t != nil {
		tsks = append(tsks, t)
	}
	return tsks
}

// environmentTasks returns the set of tasks that should be run to identify what is being scanned or the context
// of where it is being scanned. Today this is used to identify the linux distribution release for container images
// being scanned.
func (c CreateSBOMConfig) environmentTasks() []task.Task {
	var tsks []task.Task

	if t := task.NewEnvironmentTask(); t != nil {
		tsks = append(tsks, t)
	}
	return tsks
}

func (c CreateSBOMConfig) validate() error {
	if c.Relationships.ExcludeBinaryPackagesWithFileOwnershipOverlap {
		if !c.Relationships.FileOwnershipOverlap {
			return fmt.Errorf("invalid configuration: to exclude binary packages based on file ownership overlap relationships, cataloging file ownership overlap relationships must be enabled")
		}
	}
	return nil
}

// Create creates an SBOM from the given source with the current SBOM configuration.
func (c CreateSBOMConfig) Create(src source.Source) (*sbom.SBOM, error) {
	return CreateSBOM(src, c)
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
