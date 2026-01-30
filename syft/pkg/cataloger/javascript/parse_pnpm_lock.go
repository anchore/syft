package javascript

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

// pnpmPackage holds the raw name and version extracted from the lockfile.
type pnpmPackage struct {
	Name         string
	Version      string
	Integrity    string
	Dependencies map[string]string
	Dev          bool
}

// pnpmLockfileParser defines the interface for parsing different versions of pnpm lockfiles.
type pnpmLockfileParser interface {
	Parse(version float64, data []byte) ([]pnpmPackage, error)
}

type pnpmV6PackageEntry struct {
	Resolution   map[string]string `yaml:"resolution"`
	Dependencies map[string]string `yaml:"dependencies"`
	Dev          bool              `yaml:"dev"`
}

// pnpmV6LockYaml represents the structure of pnpm lockfiles for versions < 9.0.
type pnpmV6LockYaml struct {
	Dependencies map[string]interface{}        `yaml:"dependencies"`
	Packages     map[string]pnpmV6PackageEntry `yaml:"packages"`
}

type pnpmV9SnapshotEntry struct {
	Dependencies               map[string]string `yaml:"dependencies"`
	Optional                   bool              `yaml:"optional"`
	OptionalDependencies       map[string]string `yaml:"optionalDependencies"`
	TransitivePeerDependencies []string          `yaml:"transitivePeerDependencies"`
}

type pnpmV9PackageEntry struct {
	Resolution       map[string]string `yaml:"resolution"`
	PeerDependencies map[string]string `yaml:"peerDependencies"`
	Dev              bool              `yaml:"dev"`
}

// pnpmV9LockYaml represents the structure of pnpm lockfiles for versions >= 9.0.
type pnpmV9LockYaml struct {
	LockfileVersion string                         `yaml:"lockfileVersion"`
	Importers       map[string]interface{}         `yaml:"importers"` // Using interface{} for forward compatibility
	Packages        map[string]pnpmV9PackageEntry  `yaml:"packages"`
	Snapshots       map[string]pnpmV9SnapshotEntry `yaml:"snapshots"`
}

type genericPnpmLockAdapter struct {
	cfg CatalogerConfig
}

func newGenericPnpmLockAdapter(cfg CatalogerConfig) genericPnpmLockAdapter {
	return genericPnpmLockAdapter{
		cfg: cfg,
	}
}

// Parse implements the pnpmLockfileParser interface for v6-v8 lockfiles.
func (p *pnpmV6LockYaml) Parse(version float64, data []byte) ([]pnpmPackage, error) {
	if err := yaml.Unmarshal(data, p); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pnpm v6 lockfile: %w", err)
	}

	packages := make(map[string]pnpmPackage)

	// Direct dependencies
	for name, info := range p.Dependencies {
		ver, err := parseVersionField(name, info)
		if err != nil {
			log.WithFields("package", name, "error", err).Trace("unable to parse pnpm dependency")
			continue
		}
		key := name + "@" + ver
		packages[key] = pnpmPackage{Name: name, Version: ver}
	}

	splitChar := "/"
	if version >= 6.0 {
		splitChar = "@"
	}

	// All transitive dependencies
	for key, pkgInfo := range p.Packages {
		name, ver, ok := parsePnpmPackageKey(key, splitChar)
		if !ok {
			log.WithFields("key", key).Trace("unable to parse pnpm package key")
			continue
		}
		pkgKey := name + "@" + ver

		integrity := ""
		if value, ok := pkgInfo.Resolution["integrity"]; ok {
			integrity = value
		}

		dependencies := make(map[string]string)
		for depName, depVersion := range pkgInfo.Dependencies {
			var normalizedVersion = strings.SplitN(depVersion, "(", 2)[0]
			dependencies[depName] = normalizedVersion
		}

		packages[pkgKey] = pnpmPackage{Name: name, Version: ver, Integrity: integrity, Dependencies: dependencies, Dev: pkgInfo.Dev}
	}

	return toSortedSlice(packages), nil
}

// Parse implements the PnpmLockfileParser interface for v9+ lockfiles.
func (p *pnpmV9LockYaml) Parse(_ float64, data []byte) ([]pnpmPackage, error) {
	if err := yaml.Unmarshal(data, p); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pnpm v9 lockfile: %w", err)
	}

	packages := make(map[string]pnpmPackage)

	// In v9, all resolved dependencies are listed in the top-level "packages" field.
	// The key format is like /<name>@<version> or /<name>@<version>(<peer-deps>).
	for key, entry := range p.Packages {
		// The separator for name and version is consistently '@' in v9+ keys.
		name, ver, ok := parsePnpmPackageKey(key, "@")
		if !ok {
			log.WithFields("key", key).Trace("unable to parse pnpm v9 package key")
			continue
		}
		pkgKey := name + "@" + ver
		packages[pkgKey] = pnpmPackage{Name: name, Version: ver, Integrity: entry.Resolution["integrity"], Dev: entry.Dev}
	}

	for key, snapshotInfo := range p.Snapshots {
		name, ver, ok := parsePnpmPackageKey(key, "@")
		if !ok {
			log.WithFields("key", key).Trace("unable to parse pnpm v9 package snapshot key")
			continue
		}
		pkgKey := name + "@" + ver
		if pkg, ok := packages[pkgKey]; ok {
			pkg.Dependencies = make(map[string]string)
			for name, versionSpecifier := range snapshotInfo.Dependencies {
				var normalizedVersion = strings.SplitN(versionSpecifier, "(", 2)[0]
				pkg.Dependencies[name] = normalizedVersion
			}
			packages[pkgKey] = pkg
		} else {
			log.WithFields("package", pkgKey).Trace("package not found in packages map")
		}
	}

	return toSortedSlice(packages), nil
}

// newPnpmLockfileParser is a factory function that returns the correct parser for the given lockfile version.
func newPnpmLockfileParser(version float64) pnpmLockfileParser {
	if version >= 9.0 {
		return &pnpmV9LockYaml{}
	}
	return &pnpmV6LockYaml{}
}

// parsePnpmLock is the main parser function for pnpm-lock.yaml files.
func (a genericPnpmLockAdapter) parsePnpmLock(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load pnpm-lock.yaml file: %w", err)
	}

	var lockfile struct {
		Version string `yaml:"lockfileVersion"`
	}
	if err := yaml.Unmarshal(data, &lockfile); err != nil {
		return nil, nil, fmt.Errorf("failed to parse pnpm-lock.yaml version: %w", err)
	}

	version, err := strconv.ParseFloat(lockfile.Version, 64)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid lockfile version %q: %w", lockfile.Version, err)
	}

	parser := newPnpmLockfileParser(version)
	pnpmPkgs, err := parser.Parse(version, data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse pnpm-lock.yaml file: %w", err)
	}

	packages := make([]pkg.Package, 0, len(pnpmPkgs))
	for _, p := range pnpmPkgs {
		if p.Dev && !a.cfg.IncludeDevDependencies {
			continue
		}
		packages = append(packages, newPnpmPackage(ctx, a.cfg, resolver, reader.Location, p.Name, p.Version, p.Integrity, p.Dependencies))
	}

	return packages, dependency.Resolve(pnpmLockDependencySpecifier, packages), unknown.IfEmptyf(packages, "unable to determine packages")
}

// parseVersionField extracts the version string from a dependency entry.
func parseVersionField(name string, info interface{}) (string, error) {
	switch v := info.(type) {
	case string:
		return v, nil
	case map[string]interface{}:
		if ver, ok := v["version"].(string); ok {
			// e.g., "1.2.3(react@17.0.0)" -> "1.2.3"
			return strings.SplitN(ver, "(", 2)[0], nil
		}
		return "", fmt.Errorf("version field is not a string for %q", name)
	default:
		return "", fmt.Errorf("unsupported dependency type %T for %q", info, name)
	}
}

// parsePnpmPackageKey extracts the package name and version from a lockfile package key.
// Handles formats like:
// - /@babel/runtime/7.16.7
// - /@types/node@14.18.12
// - /is-glob@4.0.3
// - /@babel/helper-plugin-utils@7.24.7(@babel/core@7.24.7)
func parsePnpmPackageKey(key, separator string) (name, version string, ok bool) {
	// Strip peer dependency information, e.g., (...)
	key = strings.SplitN(key, "(", 2)[0]

	// Strip leading slash
	key = strings.TrimPrefix(key, "/")

	parts := strings.Split(key, separator)
	if len(parts) < 2 {
		return "", "", false
	}

	version = parts[len(parts)-1]
	name = strings.Join(parts[:len(parts)-1], separator)

	return name, version, true
}

// toSortedSlice converts the map of packages to a sorted slice for deterministic output.
func toSortedSlice(packages map[string]pnpmPackage) []pnpmPackage {
	pkgs := make([]pnpmPackage, 0, len(packages))
	for _, p := range packages {
		pkgs = append(pkgs, p)
	}

	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name == pkgs[j].Name {
			return pkgs[i].Version < pkgs[j].Version
		}
		return pkgs[i].Name < pkgs[j].Name
	})

	return pkgs
}
