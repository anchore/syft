package javascript

import (
	"context"
	"encoding/json"
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

// bunPackage holds the raw name, version, and metadata extracted from the lockfile.
type bunPackage struct {
	Name         string
	Version      string
	Identifier   string
	Resolved     string
	Integrity    string
	Dependencies map[string]pkg.BunLockPackageDependencies
}

// bunLockfile represents the structure of a bun.lock file (JSON format).
type bunLockfile struct {
	LockfileVersion int                        `json:"lockfileVersion"`
	ConfigVersion   int                        `json:"configVersion"`
	Workspaces      map[string]bunWorkspace    `json:"workspaces"`
	Packages        map[string]json.RawMessage `json:"packages"`
}

type bunWorkspace struct {
	Name            string            `json:"name"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

type genericBunLockAdapter struct {
	cfg CatalogerConfig
}

func newGenericBunLockAdapter(cfg CatalogerConfig) genericBunLockAdapter {
	return genericBunLockAdapter{
		cfg: cfg,
	}
}

// parseBunLock is the main parser function for bun.lock files.
func (a genericBunLockAdapter) parseBunLock(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load bun.lock file: %w", err)
	}

	var lockfile bunLockfile
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, nil, fmt.Errorf("failed to parse bun.lock file: %w", err)
	}

	log.WithFields("lockfileVersion", lockfile.LockfileVersion, "configVersion", lockfile.ConfigVersion).Trace("parsed bun.lock metadata")

	bunPkgs, err := parseBunLockPackages(lockfile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse bun.lock packages: %w", err)
	}

	// Collect dev dependencies from all workspaces
	devDeps := make(map[string]bool)
	for _, workspace := range lockfile.Workspaces {
		for devDepName := range workspace.DevDependencies {
			devDeps[devDepName] = true
		}
	}

	// Determine dev-only packages
	prodDeps := make(map[string]string)
	for _, workspace := range lockfile.Workspaces {
		for name, version := range workspace.Dependencies {
			prodDeps[name] = version
		}
	}

	devOnlyPkgs := findDevOnlyBunPkgs(bunPkgs, prodDeps, devDeps)

	packages := make([]pkg.Package, 0, len(bunPkgs))
	for _, p := range bunPkgs {
		if devOnlyPkgs[p.Name] && !a.cfg.IncludeDevDependencies {
			continue
		}
		packages = append(packages, newBunPackage(ctx, a.cfg, resolver, reader.Location, p.Name, p.Version, p.Integrity, p.Dependencies))
	}

	pkg.Sort(packages)

	return packages, dependency.Resolve(bunLockDependencySpecifier, packages), unknown.IfEmptyf(packages, "unable to determine packages")
}

func parseBunLockPackages(lockfile bunLockfile) ([]bunPackage, error) {
	packages := make([]bunPackage, 0, len(lockfile.Packages))

	for pkgName, pkgData := range lockfile.Packages {
		var pkgArray []json.RawMessage
		if err := json.Unmarshal(pkgData, &pkgArray); err != nil {
			return nil, fmt.Errorf("failed to parse bun.lock package entry %q: %w", pkgName, err)
		}

		if len(pkgArray) < 4 {
			return nil, fmt.Errorf("bun.lock package entry %q has unexpected format: expected at least 4 elements, got %d", pkgName, len(pkgArray))
		}

		// Extract identifier (name@version) from first element
		var identifier string
		if err := json.Unmarshal(pkgArray[0], &identifier); err != nil {
			log.WithFields("package", pkgName, "error", err).Trace("unable to parse bun.lock package identifier")
			continue
		}

		// Parse identifier to handle scoped packages (@scope/name@version)
		name, version, ok := parseBunPackageIdentifier(identifier)
		if !ok {
			log.WithFields("identifier", identifier).Trace("unable to parse bun.lock package identifier format")
			continue
		}

		var resolved string
		if err := json.Unmarshal(pkgArray[1], &resolved); err != nil {
			log.WithFields("package", pkgName, "error", err).Trace("unable to parse bun.lock package resolved")
		}

		var metadata pkg.BunLockPackageDependencies
		if err := json.Unmarshal(pkgArray[2], &metadata); err != nil {
			log.WithFields("package", pkgName, "error", err).Trace("unable to parse bun.lock package metadata")
		}

		var integrity string
		if err := json.Unmarshal(pkgArray[3], &integrity); err != nil {
			log.WithFields("package", pkgName, "error", err).Trace("unable to parse bun.lock package integrity")
		}

		dependencies := make(map[string]pkg.BunLockPackageDependencies)
		if len(metadata.Dependencies) > 0 || len(metadata.OptionalDependencies) > 0 || len(metadata.PeerDependencies) > 0 || len(metadata.Bin) > 0 || metadata.OS != "" || metadata.CPU != "" {
			dependencies[name] = metadata
		}

		packages = append(packages, bunPackage{
			Name:         name,
			Version:      version,
			Identifier:   identifier,
			Resolved:     resolved,
			Integrity:    integrity,
			Dependencies: dependencies,
		})
	}

	return packages, nil
}

// parseBunPackageIdentifier extracts the package name and version from a bun.lock identifier.
func parseBunPackageIdentifier(identifier string) (name, version string, ok bool) {
	// Find the last @ symbol which separates name from version
	lastAtIndex := strings.LastIndex(identifier, "@")
	if lastAtIndex == -1 {
		return "", "", false
	}

	// Handle scoped packages (@scope/package@version)
	if strings.HasPrefix(identifier, "@") && lastAtIndex > 0 {
		name = identifier[:lastAtIndex]
		version = identifier[lastAtIndex+1:]
		return name, version, true
	}

	// Handle non-scoped packages (package@version)
	name = identifier[:lastAtIndex]
	version = identifier[lastAtIndex+1:]
	return name, version, true
}

func findDevOnlyBunPkgs(bunPkgs []bunPackage, prodDeps map[string]string, devDeps map[string]bool) map[string]bool {
	// Build a simplified dependency graph
	depGraph := make(map[string][]string)
	for _, p := range bunPkgs {
		var deps []string
		for _, metadata := range p.Dependencies {
			for depName := range metadata.Dependencies {
				deps = append(deps, depName)
			}
			for depName := range metadata.OptionalDependencies {
				deps = append(deps, depName)
			}
		}
		depGraph[p.Name] = deps
	}

	// Find all packages reachable from production dependencies
	prodReachable := make(map[string]bool)
	var visitProd func(string)
	visitProd = func(name string) {
		if prodReachable[name] {
			return
		}
		prodReachable[name] = true
		for _, dep := range depGraph[name] {
			visitProd(dep)
		}
	}

	for prodDep := range prodDeps {
		visitProd(prodDep)
	}

	// Find all packages reachable from dev dependencies
	devReachable := make(map[string]bool)
	var visitDev func(string)
	visitDev = func(name string) {
		if devReachable[name] {
			return
		}
		devReachable[name] = true
		for _, dep := range depGraph[name] {
			visitDev(dep)
		}
	}

	for devDep := range devDeps {
		visitDev(devDep)
	}

	// Packages that are dev-only are those reachable from dev but not from prod
	devOnly := make(map[string]bool)
	for name := range devReachable {
		if !prodReachable[name] {
			devOnly[name] = true
		}
	}

	return devOnly
}
