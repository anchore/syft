/*
Package nix provides a concrete Cataloger implementation for packages within the Nix packaging ecosystem.
*/
package nix

import (
	"context"
	"errors"
	"fmt"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/licenses"
)

// storeCataloger finds package outputs installed in the Nix store location (/nix/store/*).
type storeCataloger struct {
	config Config
	name   string
}

// NewStoreCataloger returns a new cataloger object initialized for Nix store files.
//
// Deprecated: please use NewCataloger instead
func NewStoreCataloger() pkg.Cataloger {
	return newStoreCataloger(Config{CaptureOwnedFiles: true}, "nix-store-cataloger")
}

func newStoreCataloger(cfg Config, name string) storeCataloger {
	return storeCataloger{
		config: cfg,
		name:   name,
	}
}

func (c storeCataloger) Name() string {
	return c.name
}

func (c storeCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	prototypes, err := c.findPackagesFromStore(ctx, resolver)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find nix packages: %w", err)
	}

	drvs, err := c.findDerivationsFromStore(resolver, prototypes)
	if err != nil {
		// preserve unknown errors, but suppress would-be fatal errors
		var cErr *unknown.CoordinateError
		if !errors.As(err, &cErr) {
			// let's ignore fatal errors from this path, since it only enriches packages
			drvs = newDerivations()
			err = nil
			log.WithFields("error", err).Trace("failed to find nix derivations")
		}
	}

	pkgs, rels := c.finalizeStorePackages(ctx, resolver, prototypes, drvs)
	return pkgs, rels, err
}

func (c storeCataloger) finalizeStorePackages(ctx context.Context, resolver file.Resolver, pkgPrototypes []nixStorePackage, drvs *derivations) ([]pkg.Package, []artifact.Relationship) {
	var pkgs []pkg.Package
	var pkgByStorePath = make(map[string]pkg.Package)
	for _, pp := range pkgPrototypes {
		if pp.Location == nil {
			continue
		}

		p := newNixStorePackage(pp, c.name)
		p = licenses.RelativeToPackage(ctx, resolver, p)
		pkgs = append(pkgs, p)
		pkgByStorePath[pp.Location.RealPath] = p
	}

	var relationships []artifact.Relationship
	for storePath, p := range pkgByStorePath {
		deps := drvs.findDependencies(storePath)
		for _, dep := range deps {
			if depPkg, ok := pkgByStorePath[dep]; ok {
				relationships = append(relationships, artifact.Relationship{
					From: depPkg,
					To:   p,
					Type: artifact.DependencyOfRelationship,
				})
			}
		}
	}
	return pkgs, relationships
}

func (c storeCataloger) findDerivationsFromStore(resolver file.Resolver, pkgPrototypes []nixStorePackage) (*derivations, error) {
	locs, err := resolver.FilesByGlob("**/nix/store/*.drv")
	if err != nil {
		return nil, fmt.Errorf("failed to find derivations: %w", err)
	}
	var errs error
	dvs := newDerivations()
	for _, loc := range locs {
		d, err := newDerivationFromLocation(loc, resolver)
		if err != nil {
			errs = unknown.Append(errs, loc.Coordinates, err)
			continue
		}
		if d == nil {
			continue
		}

		dvs.add(*d)
	}

	// attach derivations to the packages they belong to
	for i := range pkgPrototypes {
		p := &pkgPrototypes[i]
		p.derivationFile = dvs.findDerivationForOutputPath(p.Location.RealPath)
	}

	return dvs, errs
}

func (c storeCataloger) findPackagesFromStore(ctx context.Context, resolver file.Resolver) ([]nixStorePackage, error) {
	// we want to search for only directories, which isn't possible via the stereoscope API, so we need to apply the glob manually on all returned paths
	var prototypes []nixStorePackage
	var filesByStorePath = make(map[string]*file.LocationSet)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for location := range resolver.AllLocations(ctx) {
		matchesStorePath, err := doublestar.Match("**/nix/store/*", location.RealPath)
		if err != nil {
			return nil, fmt.Errorf("failed to match nix store path: %w", err)
		}

		parentStorePath := findParentNixStorePath(location.RealPath)
		if c.config.CaptureOwnedFiles && parentStorePath != "" {
			fileInfo, err := resolver.FileMetadataByLocation(location)
			if err != nil {
				log.WithFields("path", location.RealPath).Trace("failed to get file metadata")
				continue
			}

			if fileInfo.IsDir() {
				// we should only add non-directories to the file set
				continue
			}

			if _, ok := filesByStorePath[parentStorePath]; !ok {
				s := file.NewLocationSet()
				filesByStorePath[parentStorePath] = &s
			}
			filesByStorePath[parentStorePath].Add(location)
		}

		if !matchesStorePath {
			continue
		}

		storePath := parseNixStorePath(location.RealPath)

		if storePath == nil || !storePath.isValidPackage() {
			continue
		}

		prototypes = append(prototypes, nixStorePackage{
			Location:     &location,
			nixStorePath: *storePath,
		})
	}

	// add file sets to packages
	for i := range prototypes {
		p := &prototypes[i]
		if p.Location == nil {
			log.WithFields("package", p.nixStorePath.Name).Debug("nix package has no evidence locations associated")
			continue
		}
		parentStorePath := p.Location.RealPath
		files, ok := filesByStorePath[parentStorePath]
		if !ok {
			log.WithFields("path", parentStorePath, "nix-store-path", parentStorePath).Debug("found a nix store file for a non-existent package")
			continue
		}
		p.Files = filePaths(files.ToSlice())
	}

	return prototypes, nil
}

func filePaths(files []file.Location) []string {
	var relativePaths []string
	for _, f := range files {
		relativePaths = append(relativePaths, f.RealPath)
	}
	return relativePaths
}
