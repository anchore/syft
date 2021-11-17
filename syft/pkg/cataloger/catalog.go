package cataloger

import (
	"fmt"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common/cpe"
	"github.com/anchore/syft/syft/source"
	"github.com/hashicorp/go-multierror"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
)

// Monitor provides progress-related data for observing the progress of a Catalog() call (published on the event bus).
type Monitor struct {
	FilesProcessed     progress.Monitorable // the number of files selected and contents analyzed from all registered catalogers
	PackagesDiscovered progress.Monitorable // the number of packages discovered from all registered catalogers
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

// Catalog a given source (container image or filesystem) with the given catalogers, returning all discovered packages.
// In order to efficiently retrieve contents from a underlying container image the content fetch requests are
// done in bulk. Specifically, all files of interest are collected from each catalogers and accumulated into a single
// request.
func Catalog(resolver source.FileResolver, theDistro *distro.Distro, catalogers ...Cataloger) (*pkg.Catalog, []artifact.Relationship, error) {
	catalog := pkg.NewCatalog()
	var allRelationships []artifact.Relationship

	// TODO: update to show relationships
	filesProcessed, packagesDiscovered := newMonitor()

	// perform analysis, accumulating errors for each failed analysis
	var errs error
	for _, theCataloger := range catalogers {
		// find packages from the underlying raw data
		packages, relationships, err := theCataloger.Catalog(resolver)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}

		catalogedPackages := len(packages)

		// TODO: update to show relationships and files
		log.Debugf("package cataloger %q discovered %d packages", theCataloger.Name(), catalogedPackages)
		packagesDiscovered.N += int64(catalogedPackages)

		for _, p := range packages {
			// generate CPEs
			p.CPEs = cpe.Generate(p)

			// generate PURL
			p.PURL = generatePackageURL(p, theDistro)

			// TODO: break out into another function (refactor this function)
			// create file-to-package relationships for files owned by the package
			owningRelationships, err := packageFileOwnershipRelationships(p, resolver)
			if err != nil {
				log.Warnf("unable to create any package-file relationships for package name=%q: %w", p.Name, err)
			} else {
				allRelationships = append(allRelationships, owningRelationships...)
			}

			// add to catalog
			catalog.Add(p)
		}

		allRelationships = append(allRelationships, relationships...)
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

	var relationships []artifact.Relationship

	for _, path := range fileOwner.OwnedFiles() {
		locations, err := resolver.FilesByPath(path)
		if err != nil {
			return nil, fmt.Errorf("unable to find path for path=%q: %w", path, err)
		}

		//if len(locations) == 0 {
		//	// TODO: this is notable, we should at least log it(?)... however, ideally there is something in the SBOM about this
		//}

		for _, l := range locations {
			relationships = append(relationships, artifact.Relationship{
				From: l.Coordinates,
				To:   p,
				Type: artifact.PackageOfRelationship,
			})
		}
	}

	return relationships, nil
}
