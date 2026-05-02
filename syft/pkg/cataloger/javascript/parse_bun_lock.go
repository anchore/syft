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

// bunLockfile is the top-level shape of a bun.lock file.
// See https://bun.sh/docs/install/lockfile for format documentation.
type bunLockfile struct {
	LockfileVersion int                        `json:"lockfileVersion"`
	Workspaces      map[string]bunWorkspace    `json:"workspaces"`
	Packages        map[string]bunPackageEntry `json:"packages"`
}

// bunWorkspace mirrors a workspace entry under the top-level "workspaces" map.
// The root workspace is keyed by "".
type bunWorkspace struct {
	Name                 string            `json:"name"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// bunPackageEntry decodes a heterogeneous JSON tuple of the form
// [name@version, source, info, integrity]. Some elements may be missing for
// non-registry sources (workspace links, git, etc.).
type bunPackageEntry struct {
	NameVersion string
	Source      string
	Info        bunPackageInfo
	Integrity   string
}

type bunPackageInfo struct {
	Dependencies         map[string]string `json:"dependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

func (e *bunPackageEntry) UnmarshalJSON(data []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("bun package entry must be an array: %w", err)
	}
	if len(raw) >= 1 {
		_ = json.Unmarshal(raw[0], &e.NameVersion)
	}
	if len(raw) >= 2 {
		_ = json.Unmarshal(raw[1], &e.Source)
	}
	if len(raw) >= 3 {
		_ = json.Unmarshal(raw[2], &e.Info)
	}
	if len(raw) >= 4 {
		_ = json.Unmarshal(raw[3], &e.Integrity)
	}
	return nil
}

type genericBunLockAdapter struct {
	cfg CatalogerConfig
}

func newGenericBunLockAdapter(cfg CatalogerConfig) genericBunLockAdapter {
	return genericBunLockAdapter{cfg: cfg}
}

// parseBunLock parses a bun.lock file and returns the discovered JavaScript packages.
func (a genericBunLockAdapter) parseBunLock(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	if pathContainsNodeModulesDirectory(reader.Path()) {
		return nil, nil, nil
	}

	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read bun.lock: %w", err)
	}

	// bun.lock is JSONC (JSON with comments and trailing commas). Strip those
	// before handing off to encoding/json.
	cleaned := stripJSONCExtras(raw)

	var lock bunLockfile
	if err := json.Unmarshal(cleaned, &lock); err != nil {
		return nil, nil, fmt.Errorf("failed to parse bun.lock: %w", err)
	}

	// classify packages as dev-only via reachability over the workspace dependency graph.
	devOnlyPkgs := findBunDevOnlyPkgs(lock)

	// bun.lock can list the same name@version under multiple keys when a
	// transitive resolution is nested (e.g. "string-width" and
	// "cliui/string-width" both pointing at string-width@4.2.3). Dedup by
	// name@version so we emit each unique package once.
	seen := map[string]struct{}{}

	var pkgs []pkg.Package
	for key, entry := range lock.Packages {
		name, version := splitBunNameVersion(entry.NameVersion)
		if name == "" {
			// fall back to deriving the name from the key path; the canonical
			// name is the last "/" segment, except scoped names (@scope/foo)
			// are kept whole when they appear bare.
			name = bunNameFromKey(key)
		}
		if name == "" {
			log.WithFields("key", key).Trace("skipping bun.lock entry with no parseable name")
			continue
		}

		if devOnlyPkgs[name] && !a.cfg.IncludeDevDependencies {
			continue
		}

		dedupKey := name + "@" + version
		if _, dup := seen[dedupKey]; dup {
			continue
		}
		seen[dedupKey] = struct{}{}

		// merge direct + peer + optional deps into a single map, mirroring how
		// the yarn lock cataloger flattens transitive deps for the dependency graph.
		mergedDeps := mergeBunDeps(entry.Info)

		pkgs = append(pkgs, newBunLockPackage(ctx, a.cfg, resolver, reader.Location, name, version, entry.Source, entry.Integrity, mergedDeps))
	}

	pkg.Sort(pkgs)

	return pkgs, dependency.Resolve(bunLockDependencySpecifier, pkgs), unknown.IfEmptyf(pkgs, "unable to determine packages")
}

// findBunDevOnlyPkgs returns the set of package names that are reachable only
// through devDependencies across all workspaces.
func findBunDevOnlyPkgs(lock bunLockfile) map[string]bool {
	pkgsByName := make(map[string]bunPackageInfo)
	for _, entry := range lock.Packages {
		name, _ := splitBunNameVersion(entry.NameVersion)
		if name == "" {
			continue
		}
		// last entry wins; for reachability that's fine since we walk by name.
		pkgsByName[name] = entry.Info
	}

	prodRoots := map[string]string{}
	devRoots := map[string]string{}
	for _, ws := range lock.Workspaces {
		for n, v := range ws.Dependencies {
			prodRoots[n] = v
		}
		for n, v := range ws.PeerDependencies {
			prodRoots[n] = v
		}
		for n, v := range ws.OptionalDependencies {
			prodRoots[n] = v
		}
		for n, v := range ws.DevDependencies {
			devRoots[n] = v
		}
	}

	prodReach := bunReachable(prodRoots, pkgsByName)
	devReach := bunReachable(devRoots, pkgsByName)

	devOnly := map[string]bool{}
	for n := range devReach {
		if !prodReach[n] {
			devOnly[n] = true
		}
	}
	return devOnly
}

func bunReachable(roots map[string]string, pkgs map[string]bunPackageInfo) map[string]bool {
	visited := map[string]bool{}
	queue := make([]string, 0, len(roots))
	for n := range roots {
		queue = append(queue, n)
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		if visited[n] {
			continue
		}
		visited[n] = true
		info, ok := pkgs[n]
		if !ok {
			continue
		}
		for d := range info.Dependencies {
			if !visited[d] {
				queue = append(queue, d)
			}
		}
		for d := range info.PeerDependencies {
			if !visited[d] {
				queue = append(queue, d)
			}
		}
		for d := range info.OptionalDependencies {
			if !visited[d] {
				queue = append(queue, d)
			}
		}
	}
	return visited
}

func mergeBunDeps(info bunPackageInfo) map[string]string {
	if len(info.Dependencies) == 0 && len(info.PeerDependencies) == 0 && len(info.OptionalDependencies) == 0 {
		return nil
	}
	out := make(map[string]string, len(info.Dependencies)+len(info.PeerDependencies)+len(info.OptionalDependencies))
	for k, v := range info.Dependencies {
		out[k] = v
	}
	for k, v := range info.PeerDependencies {
		if _, exists := out[k]; !exists {
			out[k] = v
		}
	}
	for k, v := range info.OptionalDependencies {
		if _, exists := out[k]; !exists {
			out[k] = v
		}
	}
	return out
}

// splitBunNameVersion parses a Bun "name@version" tuple. Scoped packages have
// a leading "@" which is part of the name and must not be treated as the
// version delimiter. Returns ("", "") when the input is unparseable.
func splitBunNameVersion(s string) (name, version string) {
	if s == "" {
		return "", ""
	}
	leading := ""
	rest := s
	if strings.HasPrefix(rest, "@") {
		leading = "@"
		rest = rest[1:]
	}
	idx := strings.LastIndex(rest, "@")
	if idx < 0 {
		return leading + rest, ""
	}
	return leading + rest[:idx], rest[idx+1:]
}

// bunNameFromKey extracts the canonical package name from a bun.lock packages-map
// key. Keys may be plain ("foo", "@types/foo") or nested resolution paths
// ("cliui/string-width", "wrap-ansi/strip-ansi/ansi-regex"). For nested keys
// the canonical name is the last segment, preserving any "@scope/" prefix.
func bunNameFromKey(key string) string {
	if key == "" {
		return ""
	}
	parts := strings.Split(key, "/")
	last := parts[len(parts)-1]
	// handle scoped tail: ".../@scope/name"
	if strings.HasPrefix(last, "@") && len(parts) >= 2 {
		// the "@scope/name" form means the previous segment is the scope.
		// example: "parent/@scope/name" -> name = "@scope/name"
		// however the more common case for scoped tails is just "@scope/name"
		// at the top level (not nested), which Split returns as ["@scope","name"].
	}
	if strings.HasPrefix(parts[0], "@") && len(parts) == 2 {
		// top-level scoped key (no nesting)
		return key
	}
	// nested scoped tail: parent/@scope/name -> "@scope/name"
	if len(parts) >= 2 && strings.HasPrefix(parts[len(parts)-2], "@") {
		return parts[len(parts)-2] + "/" + last
	}
	return last
}

// stripJSONCExtras returns a strict JSON byte slice by removing JSONC features
// (line comments, block comments, trailing commas) while preserving string contents.
// bun.lock is documented as JSONC; strict encoding/json cannot parse trailing commas.
//
// Implemented as two passes so that a trailing comma followed by a comment
// (e.g. `[1,2,3,] // note`) is still recognized as trailing once the comment
// has been removed.
func stripJSONCExtras(in []byte) []byte {
	return stripTrailingCommas(stripJSONCComments(in))
}

func stripJSONCComments(in []byte) []byte {
	out := make([]byte, 0, len(in))
	inString := false
	escaped := false
	i := 0
	for i < len(in) {
		c := in[i]

		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			i++
			continue
		}

		if c == '"' {
			inString = true
			out = append(out, c)
			i++
			continue
		}

		// line comment: drop until newline (keep the newline so line numbers in
		// downstream JSON errors line up with the source file).
		if c == '/' && i+1 < len(in) && in[i+1] == '/' {
			for i < len(in) && in[i] != '\n' {
				i++
			}
			continue
		}

		// block comment: drop everything through the closing "*/".
		if c == '/' && i+1 < len(in) && in[i+1] == '*' {
			i += 2
			for i+1 < len(in) && !(in[i] == '*' && in[i+1] == '/') {
				i++
			}
			if i+1 < len(in) {
				i += 2
			} else {
				// unterminated block comment — bail out by skipping the rest.
				i = len(in)
			}
			continue
		}

		out = append(out, c)
		i++
	}
	return out
}

func stripTrailingCommas(in []byte) []byte {
	out := make([]byte, 0, len(in))
	inString := false
	escaped := false
	i := 0
	for i < len(in) {
		c := in[i]

		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			i++
			continue
		}

		if c == '"' {
			inString = true
			out = append(out, c)
			i++
			continue
		}

		if c == ',' {
			j := i + 1
			for j < len(in) && (in[j] == ' ' || in[j] == '\t' || in[j] == '\n' || in[j] == '\r') {
				j++
			}
			if j < len(in) && (in[j] == ']' || in[j] == '}') {
				i++
				continue
			}
		}

		out = append(out, c)
		i++
	}
	return out
}
