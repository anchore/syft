package rust

import (
	"net/url"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/pelletier/go-toml"

	"github.com/anchore/syft/syft/pkg"
)

type cargoDependencyMatch int

const (
	cargoNoMatch cargoDependencyMatch = iota
	cargoMatch
	cargoUnknownMatch
)

type cargoDependencyRequirement struct {
	name       string
	constraint *cargoVersionRequirement
	known      bool
	entry      *toml.Tree
}

type cargoDependencyScopes struct {
	dev        []cargoDependencyRequirement
	production []cargoDependencyRequirement
	patched    bool
}

func newCargoDependencyScopes(tree *toml.Tree) cargoDependencyScopes {
	scopes := cargoDependencyScopes{patched: tree.Get("patch") != nil || tree.Get("replace") != nil}
	for _, table := range cargoDependencyTables(tree) {
		scopes.dev = append(scopes.dev, cargoDependencyRequirements(table, tree, "dev-dependencies")...)
		scopes.production = append(scopes.production, cargoDependencyRequirements(table, tree, "dependencies")...)
		scopes.production = append(scopes.production, cargoDependencyRequirements(table, tree, "build-dependencies")...)
	}
	return scopes
}

func cargoDependencyRequirements(table, workspace *toml.Tree, section string) []cargoDependencyRequirement {
	deps, ok := table.GetPath([]string{section}).(*toml.Tree)
	if !ok {
		return nil
	}
	var requirements []cargoDependencyRequirement
	for _, alias := range deps.Keys() {
		requirement := cargoDependencyRequirement{name: alias}
		version, _ := deps.GetPath([]string{alias}).(string)
		requirement.entry, _ = cargoDependencyEntry(deps, workspace, alias)
		if entry := requirement.entry; entry != nil {
			if renamed, ok := entry.Get("package").(string); ok {
				requirement.name = renamed
			}
			version, _ = entry.Get("version").(string)
		} else if version == "" {
			// An unresolved inherited declaration might rename any crate.
			requirement.name = ""
		}
		requirement.constraint, requirement.known = cargoVersionConstraint(version)
		requirements = append(requirements, requirement)
	}
	return requirements
}

func (r cargoDependencyRequirement) matches(p pkg.Package, patched bool) cargoDependencyMatch {
	if r.name == "" {
		return cargoUnknownMatch
	}
	if r.name != p.Name {
		return cargoNoMatch
	}
	if !r.known {
		return cargoUnknownMatch
	}
	if r.constraint != nil {
		version, err := semver.StrictNewVersion(p.Version)
		if err != nil {
			return cargoUnknownMatch
		}
		if !r.constraint.matches(version) {
			return cargoNoMatch
		}
	}
	match := cargoDependencySourceMatch(r.entry, p.Metadata.(pkg.RustCargoLockEntry).Source)
	if match == cargoNoMatch && patched {
		// Overrides can replace a declared registry or git source. Without
		// resolving Cargo's overrides, a normal use is still possible.
		return cargoUnknownMatch
	}
	return match
}

func cargoDependencySourceMatch(entry *toml.Tree, source string) cargoDependencyMatch {
	if entry != nil {
		if git, ok := entry.Get("git").(string); ok {
			if source == "" {
				return cargoUnknownMatch
			}
			return cargoGitSourceMatch(entry, git, source)
		}
		if entry.Get("path") != nil {
			if source == "" {
				return cargoMatch
			}
			return cargoNoMatch
		}
		if entry.Get("registry") != nil || entry.Get("registry-index") != nil {
			return cargoUnknownMatch // registry names require Cargo configuration
		}
	}
	if strings.HasPrefix(source, "registry+") {
		return cargoMatch
	}
	if source == "" {
		return cargoUnknownMatch // a registry dependency may have a local patch
	}
	return cargoNoMatch
}

func cargoGitSourceMatch(entry *toml.Tree, git, source string) cargoDependencyMatch {
	if !strings.HasPrefix(source, "git+") {
		return cargoNoMatch
	}
	locked, err := url.Parse(strings.TrimPrefix(source, "git+"))
	if err != nil {
		return cargoUnknownMatch
	}
	declared, err := url.Parse(git)
	if err != nil {
		return cargoUnknownMatch
	}
	if cargoGitRepository(locked) != cargoGitRepository(declared) {
		return cargoNoMatch
	}
	for _, key := range []string{"branch", "tag", "rev"} {
		ref, _ := entry.Get(key).(string)
		lockedRef := locked.Query().Get(key)
		if ref != lockedRef {
			if ref == "" || lockedRef == "" {
				return cargoUnknownMatch
			}
			return cargoNoMatch
		}
	}
	return cargoMatch
}

func cargoGitRepository(repository *url.URL) string {
	scheme := strings.ToLower(repository.Scheme)
	host := strings.ToLower(repository.Host)
	repositoryPath := strings.TrimRight(repository.Path, "/")
	if host == "github.com" {
		// Cargo canonicalizes GitHub repository URLs across protocols and
		// treats their paths case-insensitively.
		scheme = "https"
		repositoryPath = strings.ToLower(repositoryPath)
	}
	repositoryPath = strings.TrimSuffix(repositoryPath, ".git")
	return scheme + "://" + host + repositoryPath
}

func (s cargoDependencyScopes) devOnly(p pkg.Package) bool {
	for _, requirement := range s.production {
		if requirement.matches(p, s.patched) != cargoNoMatch {
			return false
		}
	}
	for _, requirement := range s.dev {
		if requirement.matches(p, s.patched) == cargoMatch {
			return true
		}
	}
	return false
}

func (s cargoDependencyScopes) devOnlyEdge(candidates []int, pkgs []pkg.Package) bool {
	if len(candidates) == 0 {
		return false
	}
	for _, candidate := range candidates {
		if !s.devOnly(pkgs[candidate]) {
			return false
		}
	}
	return true
}
