package syft

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/scylladb/go-set/strset"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/relationship"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// CreateSBOM creates a software bill-of-materials from the given source. If the CreateSBOMConfig is nil, then
// default options will be used.
func CreateSBOM(ctx context.Context, src source.Source, cfg *CreateSBOMConfig) (*sbom.SBOM, error) {
	if cfg == nil {
		cfg = DefaultCreateSBOMConfig()
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	srcMetadata := src.Describe()

	taskGroups, audit, err := cfg.makeTaskGroups(srcMetadata)
	if err != nil {
		return nil, err
	}

	resolver, err := src.FileResolver(cfg.Search.Scope)
	if err != nil {
		return nil, fmt.Errorf("unable to get file resolver: %w", err)
	}

	s := sbom.SBOM{
		Source: srcMetadata,
		Descriptor: sbom.Descriptor{
			Name:    cfg.ToolName,
			Version: cfg.ToolVersion,
			Configuration: configurationAuditTrail{
				Search:         cfg.Search,
				Relationships:  cfg.Relationships,
				DataGeneration: cfg.DataGeneration,
				Packages:       cfg.Packages,
				Files:          cfg.Files,
				Catalogers:     *audit,
				ExtraConfigs:   cfg.ToolConfiguration,
			},
		},
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(),
		},
	}

	catalogingProgress := monitorCatalogingTask(src.ID(), taskGroups)
	packageCatalogingProgress := monitorPackageCatalogingTask(s.Artifacts.Packages)

	builder := sbomsync.NewBuilder(&s)
	for i := range taskGroups {
		err := task.NewTaskExecutor(taskGroups[i], cfg.Parallelism).Execute(ctx, resolver, builder, catalogingProgress)
		if err != nil {
			// TODO: tie this to the open progress monitors...
			return nil, fmt.Errorf("failed to run tasks: %w", err)
		}
	}

	packageCatalogingProgress.SetCompleted()
	catalogingProgress.SetCompleted()

	relationship.Finalize(builder, cfg.Relationships, src)

	return &s, nil
}

func monitorPackageCatalogingTask(pkgs *pkg.Collection) *monitor.CatalogerTaskProgress {
	info := monitor.GenericTask{
		Title: monitor.Title{
			Default: "Packages",
		},
		ID:            monitor.PackageCatalogingTaskID,
		HideOnSuccess: false,
		ParentID:      monitor.TopLevelCatalogingTaskID,
	}

	prog := bus.StartCatalogerTask(info, -1, "")

	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()

		for {
			<-ticker.C

			count := humanize.Comma(int64(pkgs.PackageCount()))
			prog.AtomicStage.Set(fmt.Sprintf("%s packages", count))

			if progress.IsCompleted(prog) {
				break
			}
		}
	}()

	return prog
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
		set.Add(td.Name())
	}
	list := set.List()
	sort.Strings(list)
	return list
}
