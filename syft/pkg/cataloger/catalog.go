package cataloger

import (
	"fmt"
	"math"
	"runtime/debug"
	"sync"

	"github.com/hashicorp/go-multierror"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common/cpe"
)

// Monitor provides progress-related data for observing the progress of a Catalog() call (published on the event bus).
type Monitor struct {
	FilesProcessed     progress.Monitorable // the number of files selected and contents analyzed from all registered catalogers
	PackagesDiscovered progress.Monitorable // the number of packages discovered from all registered catalogers
}

// catalogResult provides the result of running a single cataloger against source
type catalogResult struct {
	Packages      []pkg.Package
	Relationships []artifact.Relationship
	// Discovered may sometimes be more than len(packages)
	Discovered int64
	Error      error
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

func runCataloger(cataloger pkg.Cataloger, resolver file.Resolver) (catalogerResult *catalogResult, err error) {
	// handle individual cataloger panics
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v at:\n%s", e, string(debug.Stack()))
		}
	}()

	catalogerResult = new(catalogResult)

	// find packages from the underlying raw data
	log.WithFields("cataloger", cataloger.Name()).Trace("cataloging started")
	packages, relationships, err := cataloger.Catalog(resolver)
	if err != nil {
		log.WithFields("cataloger", cataloger.Name()).Warn("error while cataloging")
		return catalogerResult, err
	}

	catalogedPackages := len(packages)

	log.WithFields("cataloger", cataloger.Name()).Debugf("discovered %d packages", catalogedPackages)
	catalogerResult.Discovered = int64(catalogedPackages)

	for _, p := range packages {
		// generate CPEs (note: this is excluded from package ID, so is safe to mutate)
		// we might have binary classified CPE already with the package so we want to append here

		dictionaryCPE, ok := cpe.DictionaryFind(p)
		if ok {
			log.Debugf("used CPE dictionary to find CPE for %s package %q: %s", p.Type, p.Name, dictionaryCPE.BindToFmtString())
			p.CPEs = append(p.CPEs, dictionaryCPE)
		} else {
			p.CPEs = append(p.CPEs, cpe.Generate(p)...)
		}

		// if we were not able to identify the language we have an opportunity
		// to try and get this value from the PURL. Worst case we assert that
		// we could not identify the language at either stage and set UnknownLanguage
		if p.Language == "" {
			p.Language = pkg.LanguageFromPURL(p.PURL)
		}

		// create file-to-package relationships for files owned by the package
		owningRelationships, err := packageFileOwnershipRelationships(p, resolver)
		if err != nil {
			log.WithFields("cataloger", cataloger.Name(), "package", p.Name, "error", err).Warnf("unable to create any package-file relationships")
		} else {
			catalogerResult.Relationships = append(catalogerResult.Relationships, owningRelationships...)
		}
		catalogerResult.Packages = append(catalogerResult.Packages, p)
	}
	catalogerResult.Relationships = append(catalogerResult.Relationships, relationships...)
	log.WithFields("cataloger", cataloger.Name()).Trace("cataloging complete")
	return catalogerResult, err
}

// Catalog a given source (container image or filesystem) with the given catalogers, returning all discovered packages.
// In order to efficiently retrieve contents from a underlying container image the content fetch requests are
// done in bulk. Specifically, all files of interest are collected from each catalogers and accumulated into a single
// request.
//
//nolint:funlen
func Catalog(resolver file.Resolver, _ *linux.Release, parallelism int, catalogers ...pkg.Cataloger) (*pkg.Collection, []artifact.Relationship, error) {
	catalog := pkg.NewCollection()
	var allRelationships []artifact.Relationship

	filesProcessed, packagesDiscovered := newMonitor()
	defer filesProcessed.SetCompleted()
	defer packagesDiscovered.SetCompleted()

	// perform analysis, accumulating errors for each failed analysis
	var errs error

	nCatalogers := len(catalogers)

	// we do not need more parallelism than there are `catalogers`.
	parallelism = int(math.Min(float64(nCatalogers), math.Max(1.0, float64(parallelism))))
	log.WithFields("parallelism", parallelism, "catalogers", nCatalogers).Debug("cataloging packages")

	jobs := make(chan pkg.Cataloger, nCatalogers)
	results := make(chan *catalogResult, nCatalogers)
	discoveredPackages := make(chan int64, nCatalogers)

	waitGroup := sync.WaitGroup{}

	for i := 0; i < parallelism; i++ {
		waitGroup.Add(1)

		go func() {
			defer waitGroup.Done()

			// wait for / get the next cataloger job available.
			for cataloger := range jobs {
				result, err := runCataloger(cataloger, resolver)

				// ensure we set the error to be aggregated
				result.Error = err

				discoveredPackages <- result.Discovered

				results <- result
			}
		}()
	}

	// dynamically show updated discovered package status
	go func() {
		for discovered := range discoveredPackages {
			packagesDiscovered.Add(discovered)
		}
	}()

	// Enqueue the jobs
	for _, cataloger := range catalogers {
		jobs <- cataloger
	}
	close(jobs)

	// Wait for the jobs to finish
	waitGroup.Wait()
	close(results)
	close(discoveredPackages)

	// collect the results
	for result := range results {
		if result.Error != nil {
			errs = multierror.Append(errs, result.Error)
		}
		for _, p := range result.Packages {
			catalog.Add(p)
		}
		allRelationships = append(allRelationships, result.Relationships...)
	}

	allRelationships = append(allRelationships, pkg.NewRelationships(catalog)...)

	return catalog, allRelationships, errs
}

func packageFileOwnershipRelationships(p pkg.Package, resolver file.PathResolver) ([]artifact.Relationship, error) {
	fileOwner, ok := p.Metadata.(pkg.FileOwner)
	if !ok {
		return nil, nil
	}

	locations := map[artifact.ID]file.Location{}

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
