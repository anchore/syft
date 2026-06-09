package javascript

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"strings"

	"github.com/tailscale/hujson"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

// bunPackage holds the name, version, and metadata extracted from a single lockfile entry.
type bunPackage struct {
	Name      string
	Version   string
	Integrity string
	Metadata  bunPackageMetadata
}

// bunPackageMetadata is the metadata object (the third element) of a bun.lock package tuple.
type bunPackageMetadata struct {
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	Bin                  map[string]string `json:"bin"`
	OS                   string            `json:"os"`
	CPU                  string            `json:"cpu"`
}

// bunLockfile represents the structure of a bun.lock file (JSONC format).
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
	data, err := io.ReadAll(reader) //nolint:gocritic // bun.lock is JSONC; the full document must be buffered for hujson.Standardize before unmarshalling
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load bun.lock file: %w", err)
	}

	// bun.lock is JSONC (JSON with comments and trailing commas), not strict JSON, so it must
	// be standardized before it can be unmarshalled. See https://bun.sh/blog/bun-lock-text-lockfile
	data, err = hujson.Standardize(data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to standardize bun.lock file: %w", err)
	}

	var lockfile bunLockfile
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, nil, fmt.Errorf("failed to parse bun.lock file: %w", err)
	}

	log.WithFields("lockfileVersion", lockfile.LockfileVersion, "configVersion", lockfile.ConfigVersion).Trace("parsed bun.lock metadata")

	bunPkgs := parseBunLockPackages(lockfile)

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
		maps.Copy(prodDeps, workspace.Dependencies)
	}

	devOnlyPkgs := findDevOnlyBunPkgs(bunPkgs, prodDeps, devDeps)

	packages := make([]pkg.Package, 0, len(bunPkgs))
	for _, p := range bunPkgs {
		if devOnlyPkgs[p.Name] && !a.cfg.IncludeDevDependencies {
			continue
		}
		packages = append(packages, newBunPackage(ctx, a.cfg, resolver, reader.Location, p.Name, p.Version, p.Integrity, p.Metadata))
	}

	pkg.Sort(packages)

	return packages, dependency.Resolve(bunLockDependencySpecifier, packages), unknown.IfEmptyf(packages, "unable to determine packages")
}

func parseBunLockPackages(lockfile bunLockfile) []bunPackage {
	packages := make([]bunPackage, 0, len(lockfile.Packages))

	for pkgName, pkgData := range lockfile.Packages {
		var pkgArray []json.RawMessage
		if err := json.Unmarshal(pkgData, &pkgArray); err != nil {
			log.WithFields("package", pkgName, "error", err).Trace("unable to parse bun.lock package entry")
			continue
		}
		if len(pkgArray) == 0 {
			continue
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

		// root, workspace, link, and file entries are local first-party packages rather than
		// resolved third-party dependencies, so they are not cataloged from the lockfile.
		if isLocalBunPackage(version) {
			continue
		}

		// tuple length and the positions of the metadata object and integrity hash vary by
		// source (registry, git, tarball), locate by type
		metadata, integrity := extractBunPackageFields(pkgName, pkgArray[1:])

		packages = append(packages, bunPackage{
			Name:      name,
			Version:   version,
			Integrity: integrity,
			Metadata:  metadata,
		})
	}

	return packages
}

// extractBunPackageFields locates the metadata object and integrity hash within the trailing
// elements of a bun.lock package tuple. Their positions vary by source: registry entries are
// [identifier, registry, {metadata}, integrity]
func extractBunPackageFields(pkgName string, elements []json.RawMessage) (bunPackageMetadata, string) {
	var metadata bunPackageMetadata
	var integrity string

	for _, raw := range elements {
		value := bytes.TrimSpace(raw)
		if len(value) == 0 {
			continue
		}

		switch value[0] {
		case '{':
			if err := json.Unmarshal(raw, &metadata); err != nil {
				log.WithFields("package", pkgName, "error", err).Trace("unable to parse bun.lock package metadata")
			}
		case '"':
			var s string
			if err := json.Unmarshal(raw, &s); err == nil && isIntegrityHash(s) {
				integrity = s
			}
		}
	}

	return metadata, integrity
}

// isIntegrityHash reports whether s is a Subresource Integrity hash (SRI format), which lets it
// be distinguished from the other string fields in a tuple
func isIntegrityHash(s string) bool {
	for _, prefix := range []string{"sha512-", "sha384-", "sha256-", "sha1-"} {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// isLocalBunPackage reports whether a package version refers to a local first-party package
// (the root project, a workspace, a symlink, or a folder) rather than a resolved third-party
// dependency. These correspond to the root/workspace/link/file resolution forms in bun.lock.
func isLocalBunPackage(version string) bool {
	for _, prefix := range []string{"root:", "workspace:", "link:", "file:"} {
		if strings.HasPrefix(version, prefix) {
			return true
		}
	}
	return false
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
		for depName := range p.Metadata.Dependencies {
			deps = append(deps, depName)
		}
		for depName := range p.Metadata.OptionalDependencies {
			deps = append(deps, depName)
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
