package cataloger

import (
	"fmt"
	"sync"

	"github.com/hashicorp/go-multierror"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common/cpe"
	"github.com/anchore/syft/syft/source"
)

// Monitor provides progress-related data for observing the progress of a Catalog() call (published on the event bus).
type Monitor struct {
	FilesProcessed     progress.Monitorable // the number of files selected and contents analyzed from all registered catalogers
	PackagesDiscovered progress.Monitorable // the number of packages discovered from all registered catalogers
}

// CatalogResult provides the result of running a single cataloger against source
type CatalogResult struct {
	Packages      []pkg.Package
	Relationships []artifact.Relationship
	Error         error
}

// newMonitor creates a new Monitor object and publishes the object on the bus as a PackageCatalogerStarted event.
func newMonitor() (*progress.Manual, *progress.Manual) {
	filesProcessed := progress.Manual{}
	packagesDiscovered := progress.Manual{}

	bus.Publish(partybus.Event{
		Type: event.PackageCatalogerStarted,
		Value: Monitor{
			FilesProcessed:     progress.Monitorable(&filesProcessed),
			PackagesDiscovered: progress.Monitorable(&packagesDiscovered),
		},
	})
	return &filesProcessed, &packagesDiscovered
}

func runCataloger(cataloger pkg.Cataloger, resolver source.FileResolver, results chan CatalogResult, progress *progress.Manual) {
	catalogerResult := new(CatalogResult)

	// find packages from the underlying raw data
	log.Debugf("cataloging with %q", cataloger.Name())
	packages, relationships, err := cataloger.Catalog(resolver)
	if err != nil {
		catalogerResult.Error = err
		results <- *catalogerResult
		log.Debugf("cataloger=%q error in handling", cataloger.Name())
		return
	}

	catalogedPackages := len(packages)

	log.Debugf("cataloger=%q discovered %d packages", cataloger.Name(), catalogedPackages)
	progress.N += int64(catalogedPackages)

	for _, p := range packages {
		// generate CPEs (note: this is excluded from package ID, so is safe to mutate)
		// we might have binary classified CPE already with the package so we want to append here
		p.CPEs = append(p.CPEs, cpe.Generate(p)...)

		// if we were not able to identify the language we have an opportunity
		// to try and get this value from the PURL. Worst case we assert that
		// we could not identify the language at either stage and set UnknownLanguage
		if p.Language == "" {
			p.Language = pkg.LanguageFromPURL(p.PURL)
		}

		// create file-to-package relationships for files owned by the package
		owningRelationships, err := packageFileOwnershipRelationships(p, resolver)
		if err != nil {
			log.Warnf("cataloger=%q unable to create any package-file relationships for package name=%q: %w", cataloger.Name(), p.Name, err)
		} else {
			catalogerResult.Relationships = append(catalogerResult.Relationships, owningRelationships...)
		}
		catalogerResult.Packages = append(catalogerResult.Packages, p)
	}
	catalogerResult.Relationships = append(catalogerResult.Relationships, relationships...)
	results <- *catalogerResult
	log.Debugf("cataloger=%q done handling", cataloger.Name())
}

// Catalog a given source (container image or filesystem) with the given catalogers, returning all discovered packages.
// In order to efficiently retrieve contents from a underlying container image the content fetch requests are
// done in bulk. Specifically, all files of interest are collected from each catalogers and accumulated into a single
// request.
func Catalog(resolver source.FileResolver, release *linux.Release, catalogers ...pkg.Cataloger) (*pkg.Catalog, []artifact.Relationship, error) {
	catalog := pkg.NewCatalog()
	var allRelationships []artifact.Relationship
	filesProcessed, packagesDiscovered := newMonitor()
	// perform analysis, accumulating errors for each failed analysis
	var errs error

	// TODO - expose workers as a flag to the cli
	workers := 1

	jobs := make(chan pkg.Cataloger, len(catalogers))
	results := make(chan CatalogResult, len(catalogers)+1)

	waitGroup := sync.WaitGroup{}

	for catalogWorkerIdx := 0; catalogWorkerIdx < workers; catalogWorkerIdx++ {
		waitGroup.Add(1)

		go func() {
			defer waitGroup.Done()

			// run each job
			for cataloger := range jobs {
				runCataloger(cataloger, resolver, results, packagesDiscovered)
			}
		}()
	}

	// Enqueue the jobs
	for _, cataloger := range catalogers {
		jobs <- cataloger
	}
	close(jobs)


	// Wait for the jobs to finish
	waitGroup.Wait()
	close(results)

	// collect the results
	for catalogResult := range results {
		if catalogResult.Error != nil {
			errs = multierror.Append(errs, catalogResult.Error)
			continue
		}
		for _, pkg := range catalogResult.Packages {
			catalog.Add(pkg)
		}
		allRelationships = append(allRelationships, catalogResult.Relationships...)
	}

	allRelationships = append(allRelationships, pkg.NewRelationships(catalog)...)

	if errs != nil {
		return nil, nil, errs
	}

	filesProcessed.SetCompleted()
	packagesDiscovered.SetCompleted()

	return catalog, allRelationships, nil
}

func packageFileOwnershipRelationships(p pkg.Package, resolver source.FilePathResolver) ([]artifact.Relationship, error) {
	fileOwner, ok := p.Metadata.(pkg.FileOwner)
	if !ok {
		return nil, nil
	}

	locations := map[artifact.ID]source.Location{}

	for _, path := range fileOwner.OwnedFiles() {
		pathRefs, err := resolver.FilesByPath(path)
		if err != nil {
			return nil, fmt.Errorf("unable to find path for path=%q: %w", path, err)
		}

		if len(pathRefs) == 0 {
			// ideally we want to warn users about missing files from a package, however, it is very common for
			// container image authors to delete files that are not needed in order to keep image sizes small. Adding
			// a warning here would be needlessly noisy (even for popular base images).
			continue
		}

		for _, ref := range pathRefs {
			if oldRef, ok := locations[ref.Coordinates.ID()]; ok {
				log.Debugf("found path duplicate of %s", oldRef.RealPath)
			}
			locations[ref.Coordinates.ID()] = ref
		}
	}

	var relationships []artifact.Relationship
	for _, location := range locations {
		relationships = append(relationships, artifact.Relationship{
			From: p,
			To:   location.Coordinates,
			Type: artifact.ContainsRelationship,
		})
	}
	return relationships, nil
}
