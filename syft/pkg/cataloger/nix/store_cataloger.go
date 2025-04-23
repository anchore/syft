/*
Package nix provides a concrete Cataloger implementation for packages within the Nix packaging ecosystem.
*/
package nix

import (
	"context"
	"errors"
	"fmt"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/nix-community/go-nix/pkg/derivation"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

const storeCatalogerName = "nix-store-cataloger"

// storeCataloger finds package outputs installed in the Nix store location (/nix/store/*).
type storeCataloger struct {
	name string
}

// NewStoreCataloger returns a new cataloger object initialized for Nix store files.
// Deprecated: please use NewCataloger instead
func NewStoreCataloger() pkg.Cataloger {
	return &storeCataloger{
		name: storeCatalogerName,
	}
}

func (c *storeCataloger) Name() string {
	return c.name
}

func (c *storeCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	prototypes, err := c.findPackagesFromStore(ctx, resolver)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find nix packages: %w", err)
	}

	derivations, err := c.findDerivationsFromStore(resolver)
	if err != nil {
		// preserve unknown errors, but suppress would-be fatal errors
		var cErr *unknown.CoordinateError
		if !errors.As(err, &cErr) {
			// let's ignore fatal errors from this path, since it only enriches packages
			derivations = newDerivationCollection()
			err = nil
			log.WithFields("error", err).Trace("failed to find nix derivations")
		}
	}

	pkgs, rels := c.finalizeStorePackages(prototypes, derivations)
	return pkgs, rels, err
}

func (c *storeCataloger) finalizeStorePackages(pkgPrototypes []nixStorePackage, derivations *derivationCollection) ([]pkg.Package, []artifact.Relationship) {
	var pkgs []pkg.Package
	var pkgByStorePath = make(map[string]pkg.Package)
	for _, pp := range pkgPrototypes {
		if pp.Location == nil {
			continue
		}

		p := newNixStorePackage(pp, derivations.findDerivationForOutput(pp.StorePath), c.name)
		pkgs = append(pkgs, p)
		pkgByStorePath[pp.Location.RealPath] = p
	}

	var relationships []artifact.Relationship
	for storePath, p := range pkgByStorePath {
		deps := derivations.findDependencies(storePath)
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

func (c *storeCataloger) findDerivationsFromStore(resolver file.Resolver) (*derivationCollection, error) {
	locs, err := resolver.FilesByGlob("**/nix/store/*.drv")
	if err != nil {
		return nil, fmt.Errorf("failed to find derivations: %w", err)
	}
	var errs error
	derivations := newDerivationCollection()
	for _, loc := range locs {
		d, err := c.getDerivation(loc, resolver)
		if err != nil {
			errs = unknown.Append(errs, loc.Coordinates, err)
			continue
		}
		if d == nil {
			continue
		}

		derivations.add(loc.RealPath, d)
	}
	return derivations, errs
}

func (c *storeCataloger) getDerivation(loc file.Location, resolver file.Resolver) (*derivation.Derivation, error) {
	r, err := resolver.FileContentsByLocation(loc)
	defer internal.CloseAndLogError(r, loc.RealPath)
	if err != nil {
		log.WithFields("path", loc.RealPath).Trace("failed to read nix derivation")
		return nil, unknown.Newf(loc.Coordinates, "failed to read nix derivation: %w", err)
	}

	d, err := derivation.ReadDerivation(r)
	if err != nil {
		log.WithFields("path", loc.RealPath).Debug("failed to parse nix derivation")
		return nil, unknown.Newf(loc.Coordinates, "failed to parse nix derivation: %w", err)
	}
	return d, nil
}

func (c *storeCataloger) findPackagesFromStore(ctx context.Context, resolver file.Resolver) ([]nixStorePackage, error) {
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
		if parentStorePath != "" {
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

		loc := location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)

		prototypes = append(prototypes, nixStorePackage{
			Location:     &loc,
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
		for _, l := range files.ToSlice() {
			p.Files = append(p.Files, l.RealPath)
		}
	}

	return prototypes, nil
}
