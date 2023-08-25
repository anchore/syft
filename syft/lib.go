/*
Package syft is a "one-stop-shop" for helper utilities for all major functionality provided by child packages of the syft library.

Here is what the main execution path for syft does:

 1. Parse a user image string to get a stereoscope image.Source object
 2. Invoke all catalogers to catalog the image, adding discovered packages to a single catalog object
 3. Invoke one or more encoders to output contents of the catalog

A Source object encapsulates the image object to be cataloged and the user options (catalog all layers vs. squashed layer),
providing a way to inspect paths and file content within the image. The Source object, not the image object, is used
throughout the main execution path. This abstraction allows for decoupling of what is cataloged (a docker image, an OCI
image, a filesystem, etc) and how it is cataloged (the individual catalogers).

Similar to the cataloging process, Linux distribution identification is also performed based on what is discovered within the image.
*/
package syft

import (
	"fmt"

	"github.com/wagoodman/go-partybus"

	"github.com/anchore/go-logger"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/source"
)

// CatalogPackages takes an inventory of packages from the given image from a particular perspective
// (e.g. squashed source, all-layers source). Returns the discovered  set of packages, the identified Linux
// distribution, and the source object used to wrap the data source.
func CatalogPackages(src source.Source, cfg cataloger.Config) (*pkg.Collection, []artifact.Relationship, *linux.Release, error) {
	resolver, err := src.FileResolver(cfg.Search.Scope)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to determine resolver while cataloging packages: %w", err)
	}

	// find the distro
	release := linux.IdentifyRelease(resolver)
	if release != nil {
		log.Infof("identified distro: %s", release.String())
	} else {
		log.Info("could not identify distro")
	}

	// if the catalogers have been configured, use them regardless of input type
	var catalogers []pkg.Cataloger
	if len(cfg.Catalogers) > 0 {
		catalogers = cataloger.AllCatalogers(cfg)
	} else {
		// otherwise conditionally use the correct set of loggers based on the input type (container image or directory)

		// TODO: this is bad, we should not be using the concrete type to determine the cataloger set
		// instead this should be a caller concern (pass the catalogers you want to use). The SBOM build PR will do this.
		switch src.(type) {
		case *source.StereoscopeImageSource:
			log.Info("cataloging an image")
			catalogers = cataloger.ImageCatalogers(cfg)
		case *source.FileSource:
			log.Info("cataloging a file")
			catalogers = cataloger.AllCatalogers(cfg)
		case *source.DirectorySource:
			log.Info("cataloging a directory")
			catalogers = cataloger.DirectoryCatalogers(cfg)
		default:
			return nil, nil, nil, fmt.Errorf("unsupported source type: %T", src)
		}
	}

	catalog, relationships, err := cataloger.Catalog(resolver, release, cfg.Parallelism, catalogers...)

	// apply exclusions to the package catalog
	// default config value for this is true
	// https://github.com/anchore/syft/issues/931
	if cfg.ExcludeBinaryOverlapByOwnership {
		for _, r := range relationships {
			if cataloger.ExcludeBinaryByFileOwnershipOverlap(r, catalog) {
				catalog.Delete(r.To.ID())
				relationships = removeRelationshipsByID(relationships, r.To.ID())
			}
		}
	}

	// no need to consider source relationships for os -> binary exclusions
	relationships = append(relationships, newSourceRelationshipsFromCatalog(src, catalog)...)
	return catalog, relationships, release, err
}

func removeRelationshipsByID(relationships []artifact.Relationship, id artifact.ID) []artifact.Relationship {
	var filtered []artifact.Relationship
	for _, r := range relationships {
		if r.To.ID() != id && r.From.ID() != id {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func newSourceRelationshipsFromCatalog(src source.Source, c *pkg.Collection) []artifact.Relationship {
	relationships := make([]artifact.Relationship, 0) // Should we pre-allocate this by giving catalog a Len() method?
	for p := range c.Enumerate() {
		relationships = append(relationships, artifact.Relationship{
			From: src,
			To:   p,
			Type: artifact.ContainsRelationship,
		})
	}

	return relationships
}

// SetLogger sets the logger object used for all syft logging calls.
func SetLogger(logger logger.Logger) {
	log.Set(logger)
}

// SetBus sets the event bus for all syft library bus publish events onto (in-library subscriptions are not allowed).
func SetBus(b *partybus.Bus) {
	bus.Set(b)
}
