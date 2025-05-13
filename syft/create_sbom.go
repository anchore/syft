package syft

import (
	"context"
	"fmt"
	"runtime"
	"sort"

	"github.com/dustin/go-humanize"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/go-sync"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
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
				Licenses:       cfg.Licenses,
				Catalogers:     *audit,
				ExtraConfigs:   cfg.ToolConfiguration,
			},
		},
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(),
		},
	}

	// setup everything we need in context: license scanner, executors, etc.
	ctx, err = setupContext(ctx, cfg)
	if err != nil {
		return nil, err
	}

	catalogingProgress := monitorCatalogingTask(src.ID(), taskGroups)
	packageCatalogingProgress := monitorPackageCatalogingTask()

	builder := sbomsync.NewBuilder(&s, monitorPackageCount(packageCatalogingProgress))
	for i := range taskGroups {
		err = sync.Collect(&ctx, cataloging.ExecutorFile, sync.ToSeq(taskGroups[i]), func(t task.Task) (any, error) {
			return nil, task.RunTask(ctx, t, resolver, builder, catalogingProgress)
		}, nil)
		if err != nil {
			// TODO: tie this to the open progress monitors...
			return nil, fmt.Errorf("failed to run tasks: %w", err)
		}
	}

	packageCatalogingProgress.SetCompleted()
	catalogingProgress.SetCompleted()

	return &s, nil
}

func setupContext(ctx context.Context, cfg *CreateSBOMConfig) (context.Context, error) {
	// configure parallel executors
	ctx = setContextExecutors(ctx, cfg)

	// configure license scanner
	// skip injecting a license scanner if one already set on context
	if licenses.IsContextLicenseScannerSet(ctx) {
		return ctx, nil
	}

	return SetContextLicenseScanner(ctx, cfg.Licenses)
}

// SetContextLicenseScanner creates and sets a license scanner
// on the provided context using the provided license config.
func SetContextLicenseScanner(ctx context.Context, cfg cataloging.LicenseConfig) (context.Context, error) {
	// inject a single license scanner and content config for all package cataloging tasks into context
	licenseScanner, err := licenses.NewDefaultScanner(
		licenses.WithCoverage(cfg.Coverage),
	)
	if err != nil {
		return nil, fmt.Errorf("could not build licenseScanner for cataloging: %w", err)
	}
	ctx = licenses.SetContextLicenseScanner(ctx, licenseScanner)
	return ctx, nil
}

func setContextExecutors(ctx context.Context, cfg *CreateSBOMConfig) context.Context {
	parallelism := 0
	if cfg != nil {
		parallelism = cfg.Parallelism
	}
	// executor parallelism is: 0 == serial, no goroutines, 1 == max 1 goroutine
	// so if they set 1, we just run in serial to avoid overhead, and treat 0 as default, reasonable max for the system
	// negative is unbounded, so no need for any other special handling
	switch parallelism {
	case 0:
		parallelism = runtime.NumCPU() * 4
	case 1:
		parallelism = 0 // run in serial, don't spawn goroutines
	case -99:
		parallelism = 1 // special case to catch incorrect executor usage during testing
	}
	// set up executors for each dimension we want to coordinate bounds for
	if !sync.HasContextExecutor(ctx, cataloging.ExecutorCPU) {
		ctx = sync.SetContextExecutor(ctx, cataloging.ExecutorCPU, sync.NewExecutor(parallelism))
	}
	if !sync.HasContextExecutor(ctx, cataloging.ExecutorFile) {
		ctx = sync.SetContextExecutor(ctx, cataloging.ExecutorFile, sync.NewExecutor(parallelism))
	}
	return ctx
}

func monitorPackageCount(prog *monitor.CatalogerTaskProgress) func(s *sbom.SBOM) {
	return func(s *sbom.SBOM) {
		count := humanize.Comma(int64(s.Artifacts.Packages.PackageCount()))
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
