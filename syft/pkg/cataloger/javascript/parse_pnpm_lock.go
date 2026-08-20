package javascript

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"maps"
	"slices"
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
// Implementations decode into themselves, so a parser is single-use: construct a new one
// per document rather than reusing one across a multi-document stream.
type pnpmLockfileParser interface {
	Parse(version float64, doc *yaml.Node) ([]pnpmPackage, error)
}

type pnpmV6PackageEntry struct {
	Resolution   map[string]string `yaml:"resolution"`
	Dependencies map[string]string `yaml:"dependencies"`
	Dev          bool              `yaml:"dev"`
}

// pnpmV6LockYaml represents the structure of pnpm lockfiles for versions < 9.0.
type pnpmV6LockYaml struct {
	Dependencies map[string]any                `yaml:"dependencies"`
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
	Importers       map[string]any                 `yaml:"importers"` // Using interface{} for forward compatibility
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
func (p *pnpmV6LockYaml) Parse(version float64, doc *yaml.Node) ([]pnpmPackage, error) {
	if err := doc.Decode(p); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pnpm v6 lockfile: %w", err)
	}

	isV5 := version < 6.0

	packages := make(map[string]pnpmPackage)

	// Direct dependencies — use sorted keys for deterministic output
	for name, info := range sortedIter(p.Dependencies) {
		ver, err := parseVersionField(name, info)
		if err != nil {
			log.WithFields("package", name, "error", err).Trace("unable to parse pnpm dependency")
			continue
		}
		if isV5 {
			ver = stripPnpmV5PeerSuffix(ver)
		}
		key := name + "@" + ver
		packages[key] = pnpmPackage{Name: name, Version: ver}
	}

	splitChar := "/"
	if version >= 6.0 {
		splitChar = "@"
	}

	// All transitive dependencies — use sorted keys for deterministic output
	for key, pkgInfo := range sortedIter(p.Packages) {
		name, ver, ok := parsePnpmPackageKey(key, splitChar)
		if !ok {
			log.WithFields("key", key).Trace("unable to parse pnpm package key")
			continue
		}
		if isV5 {
			ver = stripPnpmV5PeerSuffix(ver)
		}
		pkgKey := name + "@" + ver

		integrity := ""
		if value, ok := pkgInfo.Resolution["integrity"]; ok {
			integrity = value
		}

		dependencies := make(map[string]string)
		for depName, depVersion := range sortedIter(pkgInfo.Dependencies) {
			var normalizedVersion = strings.SplitN(depVersion, "(", 2)[0]
			if isV5 {
				normalizedVersion = stripPnpmV5PeerSuffix(normalizedVersion)
			}
			dependencies[depName] = normalizedVersion
		}

		packages[pkgKey] = pnpmPackage{Name: name, Version: ver, Integrity: integrity, Dependencies: dependencies, Dev: pkgInfo.Dev}
	}

	return toSortedSlice(packages), nil
}

// Parse implements the PnpmLockfileParser interface for v9+ lockfiles.
func (p *pnpmV9LockYaml) Parse(_ float64, doc *yaml.Node) ([]pnpmPackage, error) {
	if err := doc.Decode(p); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pnpm v9 lockfile: %w", err)
	}

	packages := make(map[string]pnpmPackage)

	// In v9, all resolved dependencies are listed in the top-level "packages" field.
	// The key format is like /<name>@<version> or /<name>@<version>(<peer-deps>).
	for key, entry := range sortedIter(p.Packages) {
		// The separator for name and version is consistently '@' in v9+ keys.
		name, ver, ok := parsePnpmPackageKey(key, "@")
		if !ok {
			log.WithFields("key", key).Trace("unable to parse pnpm v9 package key")
			continue
		}
		pkgKey := name + "@" + ver
		packages[pkgKey] = pnpmPackage{Name: name, Version: ver, Integrity: entry.Resolution["integrity"], Dev: entry.Dev}
	}

	for key, snapshotInfo := range sortedIter(p.Snapshots) {
		name, ver, ok := parsePnpmPackageKey(key, "@")
		if !ok {
			log.WithFields("key", key).Trace("unable to parse pnpm v9 package snapshot key")
			continue
		}
		pkgKey := name + "@" + ver
		if pkg, ok := packages[pkgKey]; ok {
			pkg.Dependencies = make(map[string]string)
			for name, versionSpecifier := range sortedIter(snapshotInfo.Dependencies) {
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
	// pnpm-lock.yaml can be a multi-document YAML stream: pnpm keeps config dependencies
	// and the pinned package-manager version in a leading document and the project's
	// dependency graph in the next one. Reading only the first document yields a
	// well-formed SBOM that contains pnpm's own release binaries and none of the
	// project's dependencies, with nothing to signal that it is wrong.
	// See https://github.com/anchore/syft/issues/5168.
	//
	// Every document is cataloged, not just the project's. The packages pnpm records for
	// itself (pnpm and its @pnpm/exe.* release binaries) are really installed on disk, so
	// they are reported as components like any other dependency. The alternative, keeping
	// only the last document, would drop them from the SBOM entirely.
	pnpmPkgs, errs := parsePnpmLockStream(reader)

	// left nil when nothing parses, so a failed lockfile reports no packages rather than an empty set
	var packages []pkg.Package
	for _, p := range toSortedSlice(pnpmPkgs) {
		if p.Dev && !a.cfg.IncludeDevDependencies {
			continue
		}
		packages = append(packages, newPnpmPackage(ctx, a.cfg, resolver, reader.Location, p.Name, p.Version, p.Integrity, p.Dependencies))
	}

	errs = unknown.Join(errs, unknown.IfEmptyf(packages, "unable to determine packages"))

	return packages, dependency.Resolve(pnpmLockDependencySpecifier, packages), errs
}

// parsePnpmLockStream reads every document of the lockfile stream, keyed by name@version.
// A document that fails to parse is reported as unknown rather than discarding the
// documents that did parse.
func parsePnpmLockStream(reader file.LocationReadCloser) (map[string]pnpmPackage, error) {
	dec := yaml.NewDecoder(reader)

	pnpmPkgs := make(map[string]pnpmPackage)
	var firstVersion float64
	var errs error

	for i := 0; ; i++ {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			// a malformed document leaves the decoder unusable, so stop reading and keep
			// what earlier documents contributed rather than dropping the whole lockfile
			errs = unknown.Appendf(errs, reader, "failed to parse pnpm-lock.yaml document %d: %v", i, err)
			break
		}

		// an empty or comment-only document decodes to a null node; skipping it keeps a
		// leading separator from failing the stream on a missing lockfileVersion
		if len(doc.Content) == 0 || doc.Content[0].Tag == "!!null" {
			continue
		}

		version, err := pnpmDocumentVersion(&doc, firstVersion)
		if err != nil {
			// no document has yielded a usable version yet, so there is nothing to parse
			return nil, unknown.Join(errs, err)
		}
		if firstVersion == 0 {
			firstVersion = version
		}

		pkgs, err := newPnpmLockfileParser(version).Parse(version, &doc)
		if err != nil {
			errs = unknown.Appendf(errs, reader, "failed to parse pnpm-lock.yaml document %d: %v", i, err)
			continue
		}
		mergePnpmPackages(pnpmPkgs, pkgs, i)
	}

	return pnpmPkgs, errs
}

// pnpmDocumentVersion reads lockfileVersion from a single document of the stream.
// Documents after the first are expected to repeat it, but one that omits it inherits the
// version already established rather than being dropped.
func pnpmDocumentVersion(doc *yaml.Node, established float64) (float64, error) {
	var lockfile struct {
		Version string `yaml:"lockfileVersion"`
	}
	if err := doc.Decode(&lockfile); err != nil {
		if established != 0 {
			return established, nil
		}
		return 0, fmt.Errorf("failed to parse pnpm-lock.yaml version: %w", err)
	}

	version, err := strconv.ParseFloat(lockfile.Version, 64)
	switch {
	case err == nil:
		return version, nil
	case established != 0:
		return established, nil
	default:
		return 0, fmt.Errorf("invalid lockfile version %q: %w", lockfile.Version, err)
	}
}

// mergePnpmPackages folds one document's packages into the running set. The whole stream
// follows a single collision rule, the same one used within a document: the last entry to
// appear wins.
func mergePnpmPackages(into map[string]pnpmPackage, pkgs []pnpmPackage, doc int) {
	for _, p := range pkgs {
		key := p.Name + "@" + p.Version
		if existing, ok := into[key]; ok && existing.Integrity != "" && p.Integrity != "" && existing.Integrity != p.Integrity {
			log.WithFields("package", key, "document", doc).Trace("conflicting integrity across pnpm-lock.yaml documents")
		}
		into[key] = p
	}
}

// parseVersionField extracts the version string from a dependency entry.
func parseVersionField(name string, info any) (string, error) {
	switch v := info.(type) {
	case string:
		return v, nil
	case map[string]any:
		if ver, ok := v["version"].(string); ok {
			// e.g., "1.2.3(react@17.0.0)" -> "1.2.3"
			return strings.SplitN(ver, "(", 2)[0], nil
		}
		return "", fmt.Errorf("version field is not a string for %q", name)
	default:
		return "", fmt.Errorf("unsupported dependency type %T for %q", info, name)
	}
}

// stripPnpmV5PeerSuffix removes the underscore-delimited peer dependency suffix used by
// pnpm v5 lockfiles, e.g. "5.3.2_acorn@8.8.0" or "4.10.0_fzn43tb6bdtdxy2s3aqevve2su" -> "5.3.2" / "4.10.0".
// Lockfile v6+ encodes the same information in parentheses, which is stripped separately.
// Only values that look like a registry version (leading digit) are stripped, so that
// link:/file:/git specifiers are left untouched.
func stripPnpmV5PeerSuffix(version string) string {
	idx := strings.Index(version, "_")
	if idx <= 0 {
		return version
	}
	if version[0] < '0' || version[0] > '9' {
		return version
	}
	return version[:idx]
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

// sortedIter returns an iterator over the map entries sorted by key, ensuring deterministic iteration order.
func sortedIter[K cmp.Ordered, V any](values map[K]V) iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		keys := slices.Collect(maps.Keys(values))
		slices.Sort(keys)
		for _, key := range keys {
			if !yield(key, values[key]) {
				return
			}
		}
	}
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
