package rust

import (
	"testing"

	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg"
)

func TestCargoDependencyScopesIdentity(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
		version  string
		source   string
		devOnly  bool
	}{
		{
			name:     "different direct versions retain production version",
			manifest: "[dependencies]\nexample = \"0.8\"\n[dev-dependencies]\nexample = \"0.9\"\n",
			version:  "0.8.5", source: "registry+example",
		},
		{
			name:     "different direct versions exclude development version",
			manifest: "[dependencies]\nexample = \"0.8\"\n[dev-dependencies]\nexample = \"0.9\"\n",
			version:  "0.9.2", source: "registry+example", devOnly: true,
		},
		{
			name:     "bare Cargo versions use caret semantics",
			manifest: "[dependencies]\nexample = \"1.2\"\n[dev-dependencies]\nexample = \"=1.9.1\"\n",
			version:  "1.9.1", source: "registry+example",
		},
		{
			name:     "version requirement conjunction",
			manifest: "[dependencies]\nexample = \">=1, <1.5\"\n[dev-dependencies]\nexample = \"~1.5\"\n",
			version:  "1.5.2", source: "registry+example", devOnly: true,
		},
		{
			name:     "same version from registry and development git source",
			manifest: "[dependencies]\nexample = \"1\"\n[dev-dependencies]\nexample = { git = \"https://example.com/repo.git\" }\n",
			version:  "1.0.0", source: "git+https://example.com/repo.git#abcd", devOnly: true,
		},
		{
			name:     "registry production source is preserved",
			manifest: "[dependencies]\nexample = \"1\"\n[dev-dependencies]\nexample = { git = \"https://example.com/repo.git\" }\n",
			version:  "1.0.0", source: "registry+example",
		},
		{
			name:     "same git repository with different branches",
			manifest: "[dependencies]\nexample = { git = \"https://example.com/repo.git\", branch = \"stable\" }\n[dev-dependencies]\nexample = { git = \"https://example.com/repo.git\", branch = \"testing\" }\n",
			version:  "1.0.0", source: "git+https://example.com/repo.git?branch=testing#abcd", devOnly: true,
		},
		{
			name:     "git production branch is preserved",
			manifest: "[dependencies]\nexample = { git = \"https://example.com/repo.git\", branch = \"stable\" }\n[dev-dependencies]\nexample = { git = \"https://example.com/repo.git\", branch = \"testing\" }\n",
			version:  "1.0.0", source: "git+https://example.com/repo.git?branch=stable#abcd",
		},
		{
			name:     "equivalent git URLs retain production usage",
			manifest: "[dependencies]\nexample = { git = \"https://example.com/repo.git/\" }\n[dev-dependencies]\nexample = { git = \"https://example.com/repo\" }\n",
			version:  "1.0.0", source: "git+https://example.com/repo.git#abcd",
		},
		{
			name:     "equivalent GitHub URL protocols and case retain production usage",
			manifest: "[dependencies]\nexample = { git = \"ssh://git@github.com/Owner/Repo.GIT/\" }\n[dev-dependencies]\nexample = { git = \"https://github.com/owner/repo\" }\n",
			version:  "1.0.0", source: "git+https://github.com/owner/repo#abcd",
		},
		{
			name:     "prerelease opt-in applies only to the declared release version",
			manifest: "[dependencies]\nexample = \"1.0.0-alpha\"\n[dev-dependencies]\nexample = \"=1.1.0-alpha\"\n",
			version:  "1.1.0-alpha", source: "registry+example", devOnly: true,
		},
		{
			name:     "unknown production constraint is retained",
			manifest: "[dependencies]\nexample = \"invalid\"\n[dev-dependencies]\nexample = \"1\"\n",
			version:  "1.0.0", source: "registry+example",
		},
		{
			name:     "unknown development constraint does not remove packages",
			manifest: "[dev-dependencies]\nexample = \"invalid\"\n",
			version:  "1.0.0", source: "registry+example",
		},
		{
			name:     "unresolved renamed production dependency is retained",
			manifest: "[dependencies]\nalias.workspace = true\n[dev-dependencies]\nexample = \"1\"\n",
			version:  "1.0.0", source: "registry+example",
		},
		{
			name:     "custom registry configuration is uncertain",
			manifest: "[dev-dependencies]\nexample = { version = \"1\", registry = \"internal\" }\n",
			version:  "1.0.0", source: "registry+https://internal.example/index",
		},
		{
			name:     "patch may redirect production dependency to development source",
			manifest: "[dependencies]\nexample = \"1\"\n[dev-dependencies]\nexample = { git = \"https://example.com/repo.git\" }\n[patch.crates-io]\nexample = { git = \"https://example.com/repo.git\" }\n",
			version:  "1.0.0", source: "git+https://example.com/repo.git#abcd",
		},
		{
			name:     "renamed versions resolve independently",
			manifest: "[dependencies]\nold = { package = \"example\", version = \"0.8\" }\n[dev-dependencies]\nnew = { package = \"example\", version = \"0.9\" }\n",
			version:  "0.9.2", source: "registry+example", devOnly: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := toml.Load(tt.manifest)
			require.NoError(t, err)
			p := newPackageFromCargoMetadata(pkg.RustCargoLockEntry{Name: "example", Version: tt.version, Source: tt.source})
			assert.Equal(t, tt.devOnly, newCargoDependencyScopes(tree).devOnly(p))
		})
	}
}

func TestCargoDevDependenciesDirectVersions(t *testing.T) {
	manifest, err := toml.Load("[dependencies]\nrand = \"0.8\"\n[dev-dependencies]\nrand = \"0.9\"\n")
	require.NoError(t, err)
	entries := []pkg.RustCargoLockEntry{
		{Name: "app", Version: "1.0.0", Dependencies: []string{"rand 0.8.5", "rand 0.9.2"}},
		{Name: "rand", Version: "0.8.5", Source: "registry+example"},
		{Name: "rand", Version: "0.9.2", Source: "registry+example", Dependencies: []string{"test-leaf"}},
		{Name: "test-leaf", Version: "1.0.0", Source: "registry+example"},
	}
	var packages []pkg.Package
	for _, entry := range entries {
		packages = append(packages, newPackageFromCargoMetadata(entry))
	}
	filtered := excludeCargoDevDependencies(packages, map[string]*toml.Tree{"app 1.0.0": manifest}, map[string]bool{"app 1.0.0": true})
	var identities []string
	for _, p := range filtered {
		identities = append(identities, p.Name+" "+p.Version)
		if p.Name == "app" {
			assert.Equal(t, []string{"rand 0.8.5"}, p.Metadata.(pkg.RustCargoLockEntry).Dependencies)
		}
	}
	assert.ElementsMatch(t, []string{"app 1.0.0", "rand 0.8.5"}, identities)
}

func TestCargoDevDependenciesDirectSources(t *testing.T) {
	manifest, err := toml.Load("[dependencies]\nexample = \"1\"\n[dev-dependencies]\nexample = { git = \"https://example.com/repo.git\" }\n")
	require.NoError(t, err)
	productionEdge := "example 1.0.0 (registry+example)"
	developmentEdge := "example 1.0.0 (git+https://example.com/repo.git)"
	entries := []pkg.RustCargoLockEntry{
		{Name: "app", Version: "1.0.0", Dependencies: []string{productionEdge, developmentEdge}},
		{Name: "example", Version: "1.0.0", Source: "registry+example"},
		{Name: "example", Version: "1.0.0", Source: "git+https://example.com/repo.git#abcd", Dependencies: []string{"test-leaf"}},
		{Name: "test-leaf", Version: "1.0.0", Source: "registry+example"},
	}
	var packages []pkg.Package
	for _, entry := range entries {
		packages = append(packages, newPackageFromCargoMetadata(entry))
	}
	filtered := excludeCargoDevDependencies(packages, map[string]*toml.Tree{"app 1.0.0": manifest}, map[string]bool{"app 1.0.0": true})
	require.Len(t, filtered, 2)
	for _, p := range filtered {
		metadata := p.Metadata.(pkg.RustCargoLockEntry)
		if p.Name == "app" {
			assert.Equal(t, []string{productionEdge}, metadata.Dependencies)
		} else {
			assert.Equal(t, "example", p.Name)
			assert.Equal(t, "registry+example", metadata.Source)
		}
	}
}

func TestCargoDevDependenciesTildeConstraint(t *testing.T) {
	manifest, err := toml.Load("[dependencies]\nexample = \"~0.0.0\"\n[dev-dependencies]\nexample = \"1\"\n")
	require.NoError(t, err)
	entries := []pkg.RustCargoLockEntry{
		{Name: "app", Version: "1.0.0", Dependencies: []string{"example 0.0.5", "example 1.0.0"}},
		{Name: "example", Version: "0.0.5", Source: "registry+example"},
		{Name: "example", Version: "1.0.0", Source: "registry+example", Dependencies: []string{"test-leaf"}},
		{Name: "test-leaf", Version: "1.0.0", Source: "registry+example"},
	}
	var packages []pkg.Package
	for _, entry := range entries {
		packages = append(packages, newPackageFromCargoMetadata(entry))
	}
	filtered := excludeCargoDevDependencies(packages, map[string]*toml.Tree{"app 1.0.0": manifest}, map[string]bool{"app 1.0.0": true})
	var identities []string
	for _, p := range filtered {
		identities = append(identities, p.Name+" "+p.Version)
	}
	assert.ElementsMatch(t, []string{"app 1.0.0", "example 0.0.5"}, identities)
}
