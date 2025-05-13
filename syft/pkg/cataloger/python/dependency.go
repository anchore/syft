package python

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/relationship"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

func poetryLockDependencySpecifier(p pkg.Package) dependency.Specification {
	meta, ok := p.Metadata.(pkg.PythonPoetryLockEntry)
	if !ok {
		log.Tracef("cataloger failed to extract poetry lock metadata for package %+v", p.Name)
		return dependency.Specification{}
	}

	// this package reference always includes the package name and no extras
	provides := []string{packageRef(p.Name, "")}

	var requires []string
	// add required dependencies (those which a marker is not present indicating it is explicitly optional or needs an extra marker)
	for _, dep := range meta.Dependencies {
		if isDependencyForExtra(dep) {
			continue
		}

		// we always have the base package requirement without any extras to get base dependencies
		requires = append(requires, packageRef(dep.Name, ""))

		// if there are extras, we need to add a requirement for each extra individually
		// for example:
		//    uvicorn = {version = ">=0.12.0", extras = ["standard", "else"]}
		// then we must install uvicorn with the extras "standard" and "else" to satisfy the requirement
		for _, extra := range dep.Extras {
			// always refer to extras with the package name (e.g. name[extra])
			// note: this must always be done independent of other extras (e.g.  name[extra1] and name[extra2] separately
			// is correct and name[extra1,extra2] will result in dependency resolution failure)
			requires = append(requires, packageRef(dep.Name, extra))
		}
	}

	var variants []dependency.ProvidesRequires
	for _, extra := range meta.Extras {
		variants = append(variants,
			dependency.ProvidesRequires{
				// always refer to extras with the package name (e.g. name[extra])
				// note: this must always be done independent of other extras (e.g.  name[extra1] and name[extra2] separately
				// is correct and name[extra1,extra2] will result in dependency resolution failure)
				Provides: []string{packageRef(p.Name, extra.Name)},
				Requires: extractPackageNames(extra.Dependencies),
			},
		)
	}

	return dependency.Specification{
		ProvidesRequires: dependency.ProvidesRequires{
			Provides: provides,
			Requires: requires,
		},
		Variants: variants,
	}
}

func isDependencyForExtra(dep pkg.PythonPoetryLockDependencyEntry) bool {
	return strings.Contains(dep.Markers, "extra ==")
}

func packageRef(name, extra string) string {
	cleanExtra := strings.TrimSpace(extra)
	cleanName := strings.TrimSpace(name)
	if cleanExtra == "" {
		return cleanName
	}
	return cleanName + "[" + cleanExtra + "]"
}

func wheelEggDependencySpecifier(p pkg.Package) dependency.Specification {
	meta, ok := p.Metadata.(pkg.PythonPackage)
	if !ok {
		log.Tracef("cataloger failed to extract wheel/egg metadata for package %+v", p.Name)
		return dependency.Specification{}
	}

	provides := []string{p.Name}

	var requires []string
	// extract dependencies from the Requires-Dist field
	// note: this also includes Extras, which are currently partially supported.
	// Specifically, we claim that a package needs all extra dependencies and a relationship will be created
	// if that dependency happens to be installed. We currently do not do any version constraint resolution
	// or similar behaviors to ensure what is installed will function correctly. This is somewhat consistent with
	// how extras function, where there tends to be a try/except around imports as an indication if that extra
	// functionality should be executed or not (there isn't a package declaration to reference at runtime).
	for _, depSpecifier := range meta.RequiresDist {
		depSpecifier = extractPackageName(depSpecifier)
		if depSpecifier == "" {
			continue
		}
		requires = append(requires, depSpecifier)
	}

	return dependency.Specification{
		ProvidesRequires: dependency.ProvidesRequires{
			Provides: provides,
			Requires: requires,
		},
	}
}

// extractPackageName removes any extras or version constraints from a given Requires-Dist field value (and
// semantically similar fields), leaving only the package name.
func extractPackageName(s string) string {
	// examples:
	// html5lib ; extra == 'html5lib'   -->  html5lib
	// soupsieve (>1.2)					-->  soupsieve

	return strings.TrimSpace(internal.SplitAny(s, "(;")[0])
}
func extractPackageNames(ss []string) []string {
	var names []string
	for _, s := range ss {
		names = append(names, extractPackageName(s))
	}
	return names
}

func wheelEggRelationships(ctx context.Context, resolver file.Resolver, pkgs []pkg.Package, rels []artifact.Relationship, err error) ([]pkg.Package, []artifact.Relationship, error) {
	if err != nil {
		return pkgs, rels, err
	}

	pkgsBySitePackageAndName := make(map[string]map[string]pkg.Package)

	for _, p := range pkgs {
		sitePackagesDir := deriveSitePackageDir(p)
		if pkgsBySitePackageAndName[sitePackagesDir] == nil {
			pkgsBySitePackageAndName[sitePackagesDir] = make(map[string]pkg.Package)
		}
		pkgsBySitePackageAndName[sitePackagesDir][p.Name] = p
	}

	var sitePackagesDirs []string
	for site := range pkgsBySitePackageAndName {
		sitePackagesDirs = append(sitePackagesDirs, site)
	}

	venvs, globalSitePackages, err := findVirtualEnvs(ctx, resolver, sitePackagesDirs)
	if err != nil {
		return nil, nil, err
	}

	relationshipsProcessor := dependency.Processor(wheelEggDependencySpecifier)
	relationshipIndex := relationship.NewIndex(rels...)

	// create relationships between packages within each global site package directory
	for _, globalSitePackage := range globalSitePackages {
		sitePkgs := collectPackages(pkgsBySitePackageAndName, []string{globalSitePackage})
		_, siteRels, err := relationshipsProcessor(sitePkgs, nil, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to resolve relationships for global site package %q: %w", globalSitePackage, err)
		}
		relationshipIndex.Add(siteRels...)
	}

	// create relationships between packages within each virtual env site package directory (that doesn't link to a global site-packages directory)
	for _, venv := range venvs {
		if venv.IncludeSystemSitePackages {
			continue
		}
		sitePkgs := collectPackages(pkgsBySitePackageAndName, []string{venv.SitePackagesPath})
		_, siteRels, err := relationshipsProcessor(sitePkgs, nil, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to resolve relationships for virtualenv site package %q: %w", venv.SitePackagesPath, err)
		}
		relationshipIndex.Add(siteRels...)
	}

	// create relationships between packages within each virtual env site package directory (that links to a global site package directory)
	for _, venv := range venvs {
		if !venv.IncludeSystemSitePackages {
			continue
		}

		globalSitePackage := venv.matchSystemPackagesPath(globalSitePackages)

		sitePkgs := collectPackages(pkgsBySitePackageAndName, []string{venv.SitePackagesPath, globalSitePackage})
		_, siteRels, err := relationshipsProcessor(sitePkgs, nil, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to resolve relationships for virtualenv + global site package path %q + %q: %w", venv.SitePackagesPath, globalSitePackage, err)
		}

		relationshipIndex.Add(siteRels...)
	}

	return pkgs, relationshipIndex.All(), err
}

func collectPackages(pkgsBySitePackageAndName map[string]map[string]pkg.Package, sites []string) []pkg.Package {
	// get packages for all sites, preferring packages from earlier sites for packages with the same name

	pkgByName := make(map[string]struct{})
	var pkgs []pkg.Package
	for _, site := range sites {
		for name, p := range pkgsBySitePackageAndName[site] {
			if _, ok := pkgByName[name]; !ok {
				pkgByName[name] = struct{}{}
				pkgs = append(pkgs, p)
			}
		}
	}

	return pkgs
}

func deriveSitePackageDir(p pkg.Package) string {
	for _, l := range packagePrimaryLocations(p) {
		sitePackageDir := extractSitePackageDir(l.RealPath)
		if sitePackageDir != "" {
			return sitePackageDir
		}
	}
	return ""
}

func packagePrimaryLocations(p pkg.Package) []file.Location {
	var locs []file.Location
	for _, l := range p.Locations.ToSlice() {
		a, ok := l.Annotations[pkg.EvidenceAnnotationKey]
		if !ok {
			continue
		}
		if a == pkg.PrimaryEvidenceAnnotation {
			locs = append(locs, l)
		}
	}
	return locs
}

func extractSitePackageDir(p string) string {
	// walk up the path until we find a site-packages or dist-packages directory
	fields := strings.Split(path.Dir(p), "/")
	for i := len(fields) - 1; i >= 0; i-- {
		if fields[i] == "site-packages" || fields[i] == "dist-packages" {
			return path.Join(fields[:i+1]...)
		}
	}
	return ""
}
