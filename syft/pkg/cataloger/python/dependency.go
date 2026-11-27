package python

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"

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
	// normalize both package name and extra to ensure case-insensitive matching per Python packaging spec
	// https://packaging.python.org/en/latest/specifications/name-normalization/
	cleanName := normalize(strings.TrimSpace(name))
	cleanExtra := normalize(strings.TrimSpace(extra))
	if cleanExtra == "" {
		return cleanName
	}
	return cleanName + "[" + cleanExtra + "]"
}

func pdmLockDependencySpecifier(p pkg.Package) dependency.Specification {
	meta, ok := p.Metadata.(pkg.PythonPdmLockEntry)
	if !ok {
		log.Tracef("cataloger failed to extract pdm lock metadata for package %+v", p.Name)
		return dependency.Specification{}
	}

	// base package provides the package name without extras
	provides := []string{p.Name}

	// base requirements from Dependencies field
	var requires []string
	for _, dep := range meta.Dependencies {
		depName := extractPackageName(dep)
		if depName == "" {
			continue
		}
		requires = append(requires, depName)
	}

	// create variants for each extras combination
	var variants []dependency.ProvidesRequires
	for _, extraVariant := range meta.Extras {
		// each extra in the variant provides packagename[extra]
		var variantProvides []string
		for _, extra := range extraVariant.Extras {
			variantProvides = append(variantProvides, packageRef(p.Name, extra))
		}

		// extract dependencies for this variant, excluding self-references
		var variantRequires []string
		for _, dep := range extraVariant.Dependencies {
			depName := extractPackageName(dep)
			if depName == "" || depName == p.Name {
				// skip empty or self-references (e.g., coverage[toml] depends on coverage==7.4.1)
				continue
			}
			variantRequires = append(variantRequires, depName)
		}

		if len(variantProvides) > 0 {
			variants = append(variants, dependency.ProvidesRequires{
				Provides: variantProvides,
				Requires: variantRequires,
			})
		}
	}

	return dependency.Specification{
		ProvidesRequires: dependency.ProvidesRequires{
			Provides: provides,
			Requires: requires,
		},
		Variants: variants,
	}
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

// extractPackageName removes any extras, version constraints or environment markers from a dependency specifier string.
// For example: "requests[security] >= 2.8.1 ; python_version < '3'" becomes "requests"
func extractPackageName(s string) string {
	// examples:
	// requests [security,tests]		--> requests
	// requests >= 2.8.1			--> requests
	// requests (>= 2.8.1)			--> requests
	// requests ; python_version < "2.7"	--> requests

	name := strings.TrimSpace(internal.SplitAny(s, "[(<!=>~;")[0])
	// normalize the name to match how packages are stored (lowercase, with hyphens instead of underscores)
	return normalize(name)
}

// extractPackageNames applies extractPackageName to each string in the slice.
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

	// some environments install packages as symlinks from a shared site-packages directory into
	// per-package directories (e.g. Nix-built python environments symlink *.dist-info dirs from the
	// environment's site-packages into /nix/store per-package outputs). Resolve these links so that
	// packages are grouped by the site-packages directory they are importable from, which is what
	// determines which packages can depend on each other.
	siteDirOverrides := findSymlinkedSitePackageDirs(ctx, resolver)

	pkgsBySitePackageAndName := make(map[string]map[string]pkg.Package)

	for _, p := range pkgs {
		sitePackagesDir := deriveSitePackageDir(p, siteDirOverrides)
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

func deriveSitePackageDir(p pkg.Package, symlinkedSiteDirs map[string]string) string {
	for _, l := range packagePrimaryLocations(p) {
		localPath := l.LocalPath()
		// the metadata file itself (e.g. a symlinked *.egg-info file) or its parent directory
		// (e.g. a symlinked *.dist-info directory) may be the target of a site-packages symlink
		if sitePackageDir, ok := symlinkedSiteDirs[localPath]; ok {
			return sitePackageDir
		}
		if sitePackageDir, ok := symlinkedSiteDirs[path.Dir(localPath)]; ok {
			return sitePackageDir
		}
		sitePackageDir := extractSitePackageDir(localPath)
		if sitePackageDir != "" {
			return sitePackageDir
		}
	}
	return ""
}

// findSymlinkedSitePackageDirs returns a map of resolved *.dist-info / *.egg-info paths to the
// site-packages (or dist-packages) directory that links to them with a symlink of the same name.
// This covers environments such as Nix-built python environments, where the effective site-packages
// directory contains only symlinks into per-package directories, which would otherwise prevent
// dependency relationships from being established between the packages in the environment.
func findSymlinkedSitePackageDirs(ctx context.Context, resolver file.Resolver) map[string]string {
	candidates := make(map[string][]string)

	for loc := range resolver.AllLocations(ctx) {
		p := loc.RealPath
		base := path.Base(p)
		if !strings.HasSuffix(base, ".dist-info") && !strings.HasSuffix(base, ".egg-info") {
			continue
		}
		parent := path.Dir(p)
		if path.Base(parent) != "site-packages" && path.Base(parent) != "dist-packages" {
			continue
		}
		metadata, err := resolver.FileMetadataByLocation(loc)
		if err != nil || metadata.Type != stereoscopeFile.TypeSymLink {
			continue
		}
		target := metadata.LinkDestination
		if target == "" {
			continue
		}
		if !path.IsAbs(target) {
			target = path.Clean(path.Join(parent, target))
		}
		candidates[target] = append(candidates[target], parent)
	}

	// a target may be linked from multiple site-packages directories; pick one deterministically
	mapping := make(map[string]string)
	for target, parents := range candidates {
		sort.Strings(parents)
		mapping[target] = parents[0]
	}
	return mapping
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
