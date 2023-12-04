package syft

import (
	"fmt"

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
func CatalogPackagesScribe(src source.Source, cfg cataloger.Config) (*pkg.Collection, []artifact.Relationship, *linux.Release, error) {
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

	if cfg.CatalogerGroup == "" {
		switch t := src.(type) {
		case *source.StereoscopeImageSource:
			cfg.CatalogerGroup = cataloger.InstallationGroup
		case *source.FileSource:
			cfg.CatalogerGroup = cataloger.AllGroup
		case *source.DirectorySource:
			cfg.CatalogerGroup = cataloger.IndexGroup
		default:
			return nil, nil, nil, fmt.Errorf("unable to determine cataloger set from scheme=%+v", t)
		}
	}

	groupCatalogers, err := cataloger.SelectGroup(cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	enabledCatalogers := cataloger.FilterCatalogers(cfg, groupCatalogers)

	catalog, relationships, err := cataloger.Catalog(resolver, release, cfg.Parallelism, enabledCatalogers...)

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
