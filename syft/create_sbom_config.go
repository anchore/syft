package syft

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/anchore/syft/internal/log"
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
	Compliance         cataloging.ComplianceConfig
	Search             cataloging.SearchConfig
	Relationships      cataloging.RelationshipsConfig
	Unknowns           cataloging.UnknownsConfig
	DataGeneration     cataloging.DataGenerationConfig
	Packages           pkgcataloging.Config
	Licenses           cataloging.LicenseConfig
	Files              filecataloging.Config
	Parallelism        int
	CatalogerSelection cataloging.SelectionRequest

	// audit what tool is being used to generate the SBOM
	ToolName          string
	ToolVersion       string
	ToolConfiguration interface{}

	packageTaskFactories       task.Factories
	packageCatalogerReferences []pkgcataloging.CatalogerReference
}

func DefaultCreateSBOMConfig() *CreateSBOMConfig {
	return &CreateSBOMConfig{
		Compliance:           cataloging.DefaultComplianceConfig(),
		Search:               cataloging.DefaultSearchConfig(),
		Relationships:        cataloging.DefaultRelationshipsConfig(),
		DataGeneration:       cataloging.DefaultDataGenerationConfig(),
		Packages:             pkgcataloging.DefaultConfig(),
		Licenses:             cataloging.DefaultLicenseConfig(),
		Files:                filecataloging.DefaultConfig(),
		Parallelism:          0, // use default: run in parallel based on number of CPUs
		packageTaskFactories: task.DefaultPackageTaskFactories(),

		// library consumers are free to override the tool values to fit their needs, however, we have some sane defaults
		// to ensure that SBOMs generated don't have missing tool metadata.
		ToolName:    "syft",
		ToolVersion: syftVersion(),
	}
}

func syftVersion() string {
	// extract the syft version from the go module info from the current binary that is running. This is useful for
	// library consumers to at least encode the version of syft that was used to generate the SBOM. Note: we don't
	// use the version info from main because it's baked in with ldflags, which we don't control for library consumers.
	// This approach won't work in all cases though, such as when the binary is stripped of the buildinfo section.

	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}

	for _, d := range buildInfo.Deps {
		if d.Path == "github.com/anchore/syft" && d.Version != "(devel)" {
			return d.Version
		}
	}

	return ""
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
	c.Parallelism = p
	return c
}

// WithComplianceConfig allows for setting the specific compliance configuration for cataloging.
func (c *CreateSBOMConfig) WithComplianceConfig(cfg cataloging.ComplianceConfig) *CreateSBOMConfig {
	c.Compliance = cfg
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

// WithUnknownsConfig allows for defining the specific behavior dealing with unknowns
func (c *CreateSBOMConfig) WithUnknownsConfig(cfg cataloging.UnknownsConfig) *CreateSBOMConfig {
	c.Unknowns = cfg
	return c
}

// WithDataGenerationConfig allows for defining what data elements that cannot be discovered from the underlying
// target being scanned that should be generated after package creation.
func (c *CreateSBOMConfig) WithDataGenerationConfig(cfg cataloging.DataGenerationConfig) *CreateSBOMConfig {
	c.DataGeneration = cfg
	return c
}

// WithPackagesConfig allows for defining any specific package cataloging behavior for syft-implemented catalogers.
func (c *CreateSBOMConfig) WithPackagesConfig(cfg pkgcataloging.Config) *CreateSBOMConfig {
	c.Packages = cfg
	return c
}

// WithLicenseConfig allows for defining any specific license cataloging behavior for syft-implemented catalogers.
func (c *CreateSBOMConfig) WithLicenseConfig(cfg cataloging.LicenseConfig) *CreateSBOMConfig {
	c.Licenses = cfg
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
func (c *CreateSBOMConfig) WithCatalogerSelection(selection cataloging.SelectionRequest) *CreateSBOMConfig {
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
	for i := range catalogerRefs {
		// ensure that all package catalogers have the package tag
		catalogerRefs[i].Tags = append(catalogerRefs[i].Tags, pkgcataloging.PackageTag)
	}
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
	scopeTasks := c.scopeTasks()
	relationshipsTasks := c.relationshipTasks(src)
	unknownTasks := c.unknownsTasks()

	pkgTasks, fileTasks, selectionEvidence, err := c.selectTasks(src)
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

	// all scope work must be done after all nodes (files and packages) have been cataloged and before the relationship
	if len(scopeTasks) > 0 {
		taskGroups = append(taskGroups, scopeTasks)
	}

	// all relationship work must be done after all nodes (files and packages) have been cataloged
	if len(relationshipsTasks) > 0 {
		taskGroups = append(taskGroups, relationshipsTasks)
	}

	// all unknowns tasks should happen after all scanning is complete
	if len(unknownTasks) > 0 {
		taskGroups = append(taskGroups, unknownTasks)
	}

	// identifying the environment (i.e. the linux release) must be done first as this is required for package cataloging
	taskGroups = append(
		[][]task.Task{
			environmentTasks,
		},
		taskGroups...,
	)

	var allTasks []task.Task
	allTasks = append(allTasks, pkgTasks...)
	allTasks = append(allTasks, fileTasks...)

	return taskGroups, &catalogerManifest{
		Requested: selectionEvidence.Request,
		Used:      formatTaskNames(allTasks),
	}, nil
}

// fileTasks returns the set of tasks that should be run to catalog files.
func (c *CreateSBOMConfig) fileTasks(cfg task.CatalogingFactoryConfig) ([]task.Task, error) {
	tsks, err := task.DefaultFileTaskFactories().Tasks(cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to create file cataloger tasks: %w", err)
	}

	return tsks, nil
}

// selectTasks returns the set of tasks that should be run to catalog packages and files.
func (c *CreateSBOMConfig) selectTasks(src source.Description) ([]task.Task, []task.Task, *task.Selection, error) {
	cfg := task.CatalogingFactoryConfig{
		SearchConfig:         c.Search,
		RelationshipsConfig:  c.Relationships,
		DataGenerationConfig: c.DataGeneration,
		PackagesConfig:       c.Packages,
		LicenseConfig:        c.Licenses,
		ComplianceConfig:     c.Compliance,
		FilesConfig:          c.Files,
	}

	persistentPkgTasks, selectablePkgTasks, err := c.allPackageTasks(cfg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to create package cataloger tasks: %w", err)
	}

	req, err := finalTaskSelectionRequest(c.CatalogerSelection, src)
	if err != nil {
		return nil, nil, nil, err
	}

	selectableFileTasks, err := c.fileTasks(cfg)
	if err != nil {
		return nil, nil, nil, err
	}

	taskGroups := [][]task.Task{
		selectablePkgTasks,
		selectableFileTasks,
	}

	finalTaskGroups, selection, err := task.SelectInGroups(taskGroups, *req)
	if err != nil {
		return nil, nil, nil, err
	}

	if deprecatedNames := deprecatedTasks(finalTaskGroups); len(deprecatedNames) > 0 {
		log.WithFields("catalogers", strings.Join(deprecatedNames, ", ")).Warn("deprecated catalogers are being used (please remove them from your configuration)")
	}

	finalPkgTasks := finalTaskGroups[0]
	finalFileTasks := finalTaskGroups[1]

	finalPkgTasks = append(finalPkgTasks, persistentPkgTasks...)

	if len(finalPkgTasks) == 0 && len(finalFileTasks) == 0 {
		return nil, nil, nil, fmt.Errorf("no catalogers selected")
	}

	logTaskNames(finalPkgTasks, "package cataloger")
	logTaskNames(finalFileTasks, "file cataloger")

	if len(finalPkgTasks) == 0 && len(finalFileTasks) == 0 {
		return nil, nil, nil, fmt.Errorf("no catalogers selected")
	}

	if len(finalPkgTasks) == 0 {
		log.Debug("no package catalogers selected")
	}

	if len(finalFileTasks) == 0 {
		if c.Files.Selection != file.NoFilesSelection {
			log.Warnf("no file catalogers selected but file selection is configured as %q (this may be unintentional)", c.Files.Selection)
		} else {
			log.Debug("no file catalogers selected")
		}
	}

	return finalPkgTasks, finalFileTasks, &selection, nil
}

func deprecatedTasks(taskGroups [][]task.Task) []string {
	// we want to identify any deprecated catalogers that are being used but default selections will always additionally select `file`
	// catalogers. For this reason, we must explicitly remove `file` catalogers in the selection request. This means if we
	// deprecate a file cataloger we will need special processing.
	_, selection, err := task.SelectInGroups(taskGroups, cataloging.SelectionRequest{DefaultNamesOrTags: []string{pkgcataloging.DeprecatedTag}, RemoveNamesOrTags: []string{filecataloging.FileTag}})
	if err != nil {
		// ignore the error, as it is not critical
		return nil
	}
	return selection.Result.List()
}

func logTaskNames(tasks []task.Task, kind string) {
	// log as tree output (like tree command)
	log.Debugf("selected %d %s tasks", len(tasks), kind)
	names := formatTaskNames(tasks)
	for idx, t := range names {
		if idx == len(tasks)-1 {
			log.Tracef("└── %s", t)
		} else {
			log.Tracef("├── %s", t)
		}
	}
}

func finalTaskSelectionRequest(req cataloging.SelectionRequest, src source.Description) (*cataloging.SelectionRequest, error) {
	if len(req.DefaultNamesOrTags) == 0 {
		defaultTags, err := findDefaultTags(src)
		if err != nil {
			return nil, fmt.Errorf("unable to determine default cataloger tag: %w", err)
		}

		req.DefaultNamesOrTags = append(req.DefaultNamesOrTags, defaultTags...)

		req.RemoveNamesOrTags = replaceDefaultTagReferences(defaultTags, req.RemoveNamesOrTags)
		req.SubSelectTags = replaceDefaultTagReferences(defaultTags, req.SubSelectTags)
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

// scopeTasks returns the set of tasks that should be run to generate additional scope information
func (c *CreateSBOMConfig) scopeTasks() []task.Task {
	var tsks []task.Task
	if c.Search.Scope == source.DeepSquashedScope {
		if t := task.NewDeepSquashedScopeCleanupTask(); t != nil {
			tsks = append(tsks, t)
		}
	}
	return tsks
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

// unknownsTasks returns a set of tasks that perform any necessary post-processing
// to identify SBOM elements as unknowns
func (c *CreateSBOMConfig) unknownsTasks() []task.Task {
	var tasks []task.Task

	if t := task.NewUnknownsLabelerTask(c.Unknowns); t != nil {
		tasks = append(tasks, t)
	}

	return tasks
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

func findDefaultTags(src source.Description) ([]string, error) {
	switch m := src.Metadata.(type) {
	case source.ImageMetadata:
		return []string{pkgcataloging.ImageTag, filecataloging.FileTag}, nil
	case source.FileMetadata, source.DirectoryMetadata:
		return []string{pkgcataloging.DirectoryTag, filecataloging.FileTag}, nil
	default:
		return nil, fmt.Errorf("unable to determine default cataloger tag for source type=%T", m)
	}
}

func replaceDefaultTagReferences(defaultTags []string, lst []string) []string {
	for i, tag := range lst {
		if strings.ToLower(tag) == "default" {
			switch len(defaultTags) {
			case 0:
				lst[i] = ""
			case 1:
				lst[i] = defaultTags[0]
			default:
				// remove the default tag and add the individual tags
				lst = append(lst[:i], append(defaultTags, lst[i+1:]...)...)
			}
		}
	}
	return lst
}
