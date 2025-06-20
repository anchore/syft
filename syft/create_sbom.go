package syft

import (
	"context"
	"fmt"
	"sort"

	"github.com/dustin/go-humanize"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// CreateSBOMStreaming creates a software bill-of-materials from the given source and streams it to the provided writer.
// If the CreateSBOMConfig is nil, then default options will be used.
func CreateSBOMStreaming(ctx context.Context, src source.Source, writer sbom.StreamingWriter, cfg *CreateSBOMConfig) error {
	if cfg == nil {
		cfg = DefaultCreateSBOMConfig()
	}
	if err := cfg.validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	srcMetadata := src.Describe()

	taskGroups, audit, err := cfg.makeTaskGroups(srcMetadata)
	if err != nil {
		return err
	}

	resolver, err := src.FileResolver(cfg.Search.Scope)
	if err != nil {
		return fmt.Errorf("unable to get file resolver: %w", err)
	}

	descriptor := sbom.Descriptor{
		Name:    cfg.ToolName,
		Version: cfg.ToolVersion,
		Configuration: configurationAuditTrail{
			Search:         cfg.Search,
			Relationships:  cfg.Relationships,
			DataGeneration: cfg.DataGeneration,
			Packages:       cfg.Packages,
			Files:          cfg.Files,
			Licenses:       cfg.Licenses,
			Catalogers:     *audit,
			ExtraConfigs:   cfg.ToolConfiguration,
		},
	}

	// inject a single license scanner and content config for all package cataloging tasks into context
	licenseScanner, err := licenses.NewDefaultScanner(
		licenses.WithIncludeLicenseContent(cfg.Licenses.IncludeUnkownLicenseContent),
		licenses.WithCoverage(cfg.Licenses.Coverage),
	)
	if err != nil {
		return fmt.Errorf("could not build licenseScanner for cataloging: %w", err)
	}
	ctx = licenses.SetContextLicenseScanner(ctx, licenseScanner)

	catalogingProgress := monitorCatalogingTask(src.ID(), taskGroups)
	packageCatalogingProgress := monitorPackageCatalogingTask()

	// Create a streaming builder that will write packages and relationships as they're discovered
	builder := sbomsync.NewStreamingBuilder(writer, monitorPackageCount(packageCatalogingProgress))

	// Initialize the streaming builder with source and descriptor information
	builder.Initialize(srcMetadata, descriptor)

	for i := range taskGroups {
		err := task.NewTaskExecutor(taskGroups[i], cfg.Parallelism).Execute(ctx, resolver, builder, catalogingProgress)
		if err != nil {
			return fmt.Errorf("failed to run tasks: %w", err)
		}
	}

	packageCatalogingProgress.SetCompleted()
	catalogingProgress.SetCompleted()

	// Finalize the streaming process
	builder.Finalize()

	return nil
}

// CreateSBOM creates a software bill-of-materials from the given source. If the CreateSBOMConfig is nil, then
// default options will be used.
func CreateSBOM(ctx context.Context, src source.Source, cfg *CreateSBOMConfig) (*sbom.SBOM, error) {
	// Create a collector to build the SBOM in memory
	collector := sbom.NewCollector()

	// Use the streaming implementation to build the SBOM
	err := CreateSBOMStreaming(ctx, src, collector, cfg)
	if err != nil {
		return nil, err
	}

	// Return the collected SBOM
	return collector.SBOM(), nil
}

func monitorPackageCount(prog *monitor.CatalogerTaskProgress) func() {
	return func() {
		count := humanize.Comma(prog.Current())
		prog.AtomicStage.Set(fmt.Sprintf("%s packages", count))
	}
}

func monitorPackageCatalogingTask() *monitor.CatalogerTaskProgress {
	info := monitor.GenericTask{
		Title: monitor.Title{
			Default: "Packages",
		},
		ID:            monitor.PackageCatalogingTaskID,
		HideOnSuccess: false,
		ParentID:      monitor.TopLevelCatalogingTaskID,
	}

	return bus.StartCatalogerTask(info, -1, "")
}

func monitorCatalogingTask(srcID artifact.ID, tasks [][]task.Task) *monitor.CatalogerTaskProgress {
	info := monitor.GenericTask{
		Title: monitor.Title{
			Default:      "Catalog contents",
			WhileRunning: "Cataloging contents",
			OnSuccess:    "Cataloged contents",
		},
		ID:            monitor.TopLevelCatalogingTaskID,
		Context:       string(srcID),
		HideOnSuccess: false,
	}

	var length int64
	for _, tg := range tasks {
		length += int64(len(tg))
	}

	return bus.StartCatalogerTask(info, length, "")
}

func formatTaskNames(tasks []task.Task) []string {
	set := strset.New()
	for _, td := range tasks {
		if td == nil {
			continue
		}
		set.Add(td.Name())
	}
	list := set.List()
	sort.Strings(list)
	return list
}
