package javascript

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

type genericNpmShrinkwrapAdapter struct {
	cfg CatalogerConfig
}

func newGenericNpmShrinkwrapAdapter(cfg CatalogerConfig) genericNpmShrinkwrapAdapter {
	return genericNpmShrinkwrapAdapter{
		cfg: cfg,
	}
}

// parseNpmShrinkwrap parses an npm-shrinkwrap.json and returns the discovered JavaScript packages.
// npm-shrinkwrap.json is structurally identical to package-lock.json; it is used by npm to lock
// dependency trees for installed tools and is published with the package (unlike package-lock.json).
func (a genericNpmShrinkwrapAdapter) parseNpmShrinkwrap(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	// in the case we find npm-shrinkwrap.json files in the node_modules directories, skip those
	// as the whole purpose of the lock file is for the specific dependencies of the root project
	if pathContainsNodeModulesDirectory(reader.Path()) {
		return nil, nil, nil
	}

	var pkgs []pkg.Package
	dec := json.NewDecoder(reader)

	var lock packageLock
	for {
		if err := dec.Decode(&lock); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to parse npm-shrinkwrap.json file: %w", err)
		}
	}

	if lock.LockfileVersion == 1 {
		for name, pkgMeta := range lock.Dependencies {
			// skip packages that are only present as a dev dependency
			if !a.cfg.IncludeDevDependencies && pkgMeta.Dev {
				continue
			}

			pkgs = append(pkgs, newShrinkwrapV1Package(ctx, a.cfg, resolver, reader.Location, name, pkgMeta))
		}
	}

	if lock.LockfileVersion == 2 || lock.LockfileVersion == 3 {
		for name, pkgMeta := range lock.Packages {
			if name == "" {
				if pkgMeta.Name == "" {
					continue
				}
				name = pkgMeta.Name
			}

			// skip packages that are only present as a dev dependency
			if !a.cfg.IncludeDevDependencies && pkgMeta.Dev {
				continue
			}

			// handles alias names
			if pkgMeta.Name != "" {
				name = pkgMeta.Name
			}

			newPkg := newShrinkwrapV2Package(ctx, a.cfg, resolver, reader.Location, getNameFromPath(name), pkgMeta)
			pkgs = append(pkgs, newPkg)
		}
	}

	pkg.Sort(pkgs)

	return pkgs, dependency.Resolve(npmShrinkwrapDependencySpecifier, pkgs), unknown.IfEmptyf(pkgs, "unable to determine packages")
}

func newShrinkwrapV1Package(ctx context.Context, cfg CatalogerConfig, resolver file.Resolver, location file.Location, name string, u lockDependency) pkg.Package {
	version := u.Version

	const aliasPrefixShrinkwrapV1 = "npm:"

	// Handles type aliases https://github.com/npm/rfcs/blob/main/implemented/0001-package-aliases.md
	if strings.HasPrefix(version, aliasPrefixShrinkwrapV1) {
		// this is an alias.
		// `"version": "npm:canonical-name@X.Y.Z"`
		canonicalPackageAndVersion := version[len(aliasPrefixShrinkwrapV1):]
		versionSeparator := strings.LastIndex(canonicalPackageAndVersion, "@")

		name = canonicalPackageAndVersion[:versionSeparator]
		version = canonicalPackageAndVersion[versionSeparator+1:]
	}

	var licenseSet pkg.LicenseSet

	if cfg.SearchRemoteLicenses {
		license, err := getLicenseFromNpmRegistry(cfg.NPMBaseURL, name, version)
		if err == nil && license != "" {
			licenseSet = pkg.NewLicenseSet(pkg.NewLicensesFromValuesWithContext(ctx, license)...)
		}
		if err != nil {
			log.Debugf("unable to extract licenses from javascript npm-shrinkwrap.json for package %s:%s: %+v", name, version, err)
		}
	}

	return finalizeLockPkg(
		ctx,
		resolver,
		location,
		pkg.Package{
			Name:      name,
			Version:   version,
			Licenses:  licenseSet,
			Locations: file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
			PURL:      packageURL(name, version),
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.NpmShrinkwrapEntry{Resolved: u.Resolved, Integrity: u.Integrity},
		},
	)
}

func newShrinkwrapV2Package(ctx context.Context, cfg CatalogerConfig, resolver file.Resolver, location file.Location, name string, u lockPackage) pkg.Package {
	var licenseSet pkg.LicenseSet

	if u.License != nil {
		licenseSet = pkg.NewLicenseSet(pkg.NewLicensesFromLocationWithContext(ctx, location, u.License...)...)
	} else if cfg.SearchRemoteLicenses {
		license, err := getLicenseFromNpmRegistry(cfg.NPMBaseURL, name, u.Version)
		if err == nil && license != "" {
			licenseSet = pkg.NewLicenseSet(pkg.NewLicensesFromValuesWithContext(ctx, license)...)
		}
		if err != nil {
			log.Debugf("unable to extract licenses from javascript npm-shrinkwrap.json for package %s:%s: %+v", name, u.Version, err)
		}
	}

	return finalizeLockPkg(
		ctx,
		resolver,
		location,
		pkg.Package{
			Name:      name,
			Version:   u.Version,
			Locations: file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
			Licenses:  licenseSet,
			PURL:      packageURL(name, u.Version),
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.NpmShrinkwrapEntry{Resolved: u.Resolved, Integrity: u.Integrity, Dependencies: u.Dependencies},
		},
	)
}


