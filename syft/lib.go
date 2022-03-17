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

	"github.com/anchore/syft/syft/artifact"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/logger"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/source"
	"github.com/wagoodman/go-partybus"
)

// CatalogPackages takes an inventory of packages from the given image from a particular perspective
// (e.g. squashed source, all-layers source). Returns the discovered  set of packages, the identified Linux
// distribution, and the source object used to wrap the data source.
func CatalogPackages(src *source.Source, cfg cataloger.Config) (*pkg.Catalog, []artifact.Relationship, *linux.Release, error) {
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

	// conditionally use the correct set of catalogers based on the scheme (container image or directory)
	if cfg.CatalogerGroup == "" {
		switch src.Metadata.Scheme {
		case source.ImageScheme:
			cfg.CatalogerGroup = cataloger.InstallationGroup
		case source.FileScheme:
			cfg.CatalogerGroup = cataloger.AllGroup
		case source.DirectoryScheme:
			cfg.CatalogerGroup = cataloger.IndexGroup
		default:
			return nil, nil, nil, fmt.Errorf("unable to determine cataloger set from scheme=%+v", src.Metadata.Scheme)
		}
	}

	groupCatalogers, err := cataloger.SelectGroup(cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	enabledCatalogers := cataloger.FilterCatalogers(cfg, groupCatalogers)

	catalog, relationships, err := cataloger.Catalog(resolver, release, enabledCatalogers...)
	if err != nil {
		return nil, nil, nil, err
	}

	return catalog, relationships, release, nil
}

// SetLogger sets the logger object used for all syft logging calls.
func SetLogger(logger logger.Logger) {
	log.Log = logger
}

// SetBus sets the event bus for all syft library bus publish events onto (in-library subscriptions are not allowed).
func SetBus(b *partybus.Bus) {
	bus.SetPublisher(b)
}
