package rust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestCargoDependencyScopes(t *testing.T) {
	tree, err := toml.Load(`
[dependencies]
shared = "1"
[build-dependencies]
builder = "1"
[dev-dependencies]
shared = "1"
builder = "1"
alias = { package = "test-helper", version = "1" }
inherited = { workspace = true }
[workspace.dependencies]
inherited = { package = "workspace-helper", version = "1" }
[target.'cfg(unix)'.dev-dependencies]
target-test = "1"
target-shared = "1"
[target.'cfg(windows)'.dependencies]
target-shared = "1"
`)
	require.NoError(t, err)
	scopes := newCargoDependencyScopes(tree)
	for name, expected := range map[string]bool{
		"test-helper": true, "workspace-helper": true, "target-test": true,
		"shared": false, "builder": false, "target-shared": false,
	} {
		p := newPackageFromCargoMetadata(pkg.RustCargoLockEntry{Name: name, Version: "1.0.0", Source: "registry+example"})
		assert.Equal(t, expected, scopes.devOnly(p), name)
	}
}

const devDependencyLock = `version = 3
[[package]]
name = "app"
version = "1.0.0"
dependencies = ["runtime", "test-helper", "builder"]
[[package]]
name = "runtime"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["shared"]
[[package]]
name = "test-helper"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["shared", "test-leaf"]
[[package]]
name = "test-leaf"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "shared"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "builder"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`

const devDependencyManifest = `
[package]
name = "app"
version = "1.0.0"
[dependencies]
runtime = "1"
[build-dependencies]
builder = "1"
[dev-dependencies]
test-helper = "1"
`

const localTestHelperManifest = "[package]\nname = \"test-helper\"\nversion = \"1.0.0\"\n[dependencies]\nshared = \"1\"\ntest-leaf = \"1\"\n"

func TestCargoLockDevDependencies(t *testing.T) {
	all := []string{"app", "runtime", "test-helper", "test-leaf", "shared", "builder"}
	production := []string{"app", "runtime", "shared", "builder"}
	localManifest := strings.Replace(devDependencyManifest, `test-helper = "1"`, `test-helper = { path = "helpers/test-helper" }`, 1)
	localLock := strings.Replace(devDependencyLock, "name = \"test-helper\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"", "name = \"test-helper\"\nversion = \"1.0.0\"", 1)
	patchedManifest := strings.Replace(devDependencyManifest, "runtime = \"1\"", "runtime = \"1\"\ntest-helper = \"1\"", 1)
	patchedManifest = strings.Replace(patchedManifest, "[dev-dependencies]\ntest-helper = \"1\"", "[dev-dependencies]\ntest-helper = {git=\"https://example.com/repo.git\"}", 1)
	patchedLock := strings.Replace(devDependencyLock, "name = \"test-helper\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"", "name = \"test-helper\"\nversion = \"1.0.0\"\nsource = \"git+https://example.com/repo.git#abcd\"", 1)
	patchConfig := "[patch.crates-io]\ntest-helper = {git=\"https://example.com/repo.git\"}\n"
	tests := []struct {
		name     string
		files    map[string]string
		include  bool
		lock     string
		lockPath string
		legacy   bool
		expected []string
	}{
		{
			name:     "exclude test-only direct and transitive dependencies but retain shared and build dependencies",
			files:    map[string]string{"Cargo.toml": devDependencyManifest},
			expected: production,
		},
		{
			name:    "include development dependencies",
			files:   map[string]string{"Cargo.toml": devDependencyManifest},
			include: true, expected: all,
		},
		{
			name:   "legacy constructor preserves default behavior and factory signature",
			files:  map[string]string{"Cargo.toml": devDependencyManifest},
			legacy: true, expected: all,
		},
		{
			name:  "Cargo configuration patch preserves shared runtime dependency",
			files: map[string]string{"Cargo.toml": patchedManifest, ".cargo/config.toml": patchConfig},
			lock:  patchedLock, expected: all,
		},
		{
			name:  "legacy Cargo configuration patch preserves shared runtime dependency",
			files: map[string]string{"Cargo.toml": patchedManifest, ".cargo/config": patchConfig},
			lock:  patchedLock, expected: all,
		},
		{
			name:  "ancestor Cargo configuration patch preserves shared runtime dependency",
			files: map[string]string{"project/Cargo.toml": patchedManifest, ".cargo/config.toml": patchConfig},
			lock:  patchedLock, lockPath: "project/Cargo.lock", expected: all,
		},
		{
			name: "workspace member receives Cargo configuration patch uncertainty",
			files: map[string]string{
				"Cargo.toml":         "[workspace]\nmembers=[\"app\"]\n",
				"app/Cargo.toml":     patchedManifest,
				".cargo/config.toml": patchConfig,
			},
			lock: patchedLock, expected: all,
		},
		{
			name: "member-local Cargo configuration patch preserves shared runtime dependency",
			files: map[string]string{
				"Cargo.toml":             "[workspace]\nmembers=[\"app\"]\n",
				"app/Cargo.toml":         patchedManifest,
				"app/.cargo/config.toml": patchConfig,
			},
			lock: patchedLock, expected: all,
		},
		{
			name: "member-local legacy Cargo configuration patch preserves shared runtime dependency",
			files: map[string]string{
				"Cargo.toml":        "[workspace]\nmembers=[\"app\"]\n",
				"app/Cargo.toml":    patchedManifest,
				"app/.cargo/config": patchConfig,
			},
			lock: patchedLock, expected: all,
		},
		{
			name: "member subdirectory configuration patch preserves shared runtime dependency",
			files: map[string]string{
				"Cargo.toml":                 "[workspace]\nmembers=[\"app\"]\n",
				"app/Cargo.toml":             patchedManifest,
				"app/src/.cargo/config.toml": patchConfig,
			},
			lock: patchedLock, expected: all,
		},
		{
			name: "one member configuration patch protects dependencies of other members",
			files: map[string]string{
				"Cargo.toml":               "[workspace]\nmembers=[\"app\", \"other\"]\n",
				"app/Cargo.toml":           patchedManifest,
				"other/Cargo.toml":         "[package]\nname=\"other\"\nversion=\"1.0.0\"\n",
				"other/.cargo/config.toml": patchConfig,
			},
			lock:     patchedLock + "\n[[package]]\nname=\"other\"\nversion=\"1.0.0\"\n",
			expected: append(append([]string{}, all...), "other"),
		},
		{
			name: "invalid member configuration preserves packages",
			files: map[string]string{
				"Cargo.toml":             "[workspace]\nmembers=[\"app\"]\n",
				"app/Cargo.toml":         devDependencyManifest,
				"app/.cargo/config.toml": "[invalid",
			},
			expected: all,
		},
		{
			name: "member configuration without patches still filters development dependencies",
			files: map[string]string{
				"Cargo.toml":                 "[workspace]\nmembers=[\"app\"]\n",
				"app/Cargo.toml":             devDependencyManifest,
				"app/src/.cargo/config.toml": "[build]\njobs=1\n",
			},
			expected: production,
		},
		{
			name:  "manifest patches remain conservative without configuration files",
			files: map[string]string{"Cargo.toml": patchedManifest + "\n" + patchConfig},
			lock:  patchedLock, expected: all,
		},
		{
			name:     "invalid Cargo configuration preserves packages",
			files:    map[string]string{"Cargo.toml": devDependencyManifest, ".cargo/config.toml": "[invalid"},
			expected: all,
		},
		{
			name:     "Cargo configuration without patches still filters development dependencies",
			files:    map[string]string{"Cargo.toml": devDependencyManifest, ".cargo/config.toml": "[build]\njobs=1\n"},
			expected: production,
		},
		{
			name:     "omitted root version defaults to zero",
			files:    map[string]string{"Cargo.toml": strings.Replace(devDependencyManifest, "version = \"1.0.0\"\n", "", 1)},
			lock:     strings.Replace(devDependencyLock, "name = \"app\"\nversion = \"1.0.0\"", "name = \"app\"\nversion = \"0.0.0\"", 1),
			expected: production,
		},
		{
			name: "omitted local dependency version defaults to zero",
			files: map[string]string{
				"Cargo.toml":                     localManifest,
				"helpers/test-helper/Cargo.toml": strings.Replace(localTestHelperManifest, "version = \"1.0.0\"\n", "", 1),
			},
			lock:     strings.Replace(localLock, "name = \"test-helper\"\nversion = \"1.0.0\"", "name = \"test-helper\"\nversion = \"0.0.0\"", 1),
			expected: production,
		},
		{
			name:     "missing manifest preserves all packages",
			expected: all,
		},
		{
			name:     "invalid manifest preserves all packages",
			files:    map[string]string{"Cargo.toml": "[invalid"},
			expected: all,
		},
		{
			name: "renamed target-specific dependency",
			files: map[string]string{"Cargo.toml": `
[package]
name = "app"
version = "1.0.0"
[dependencies]
runtime = "1"
[build-dependencies]
builder = "1"
[target.'cfg(unix)'.dev-dependencies]
alias = { package = "test-helper", version = "1" }
`},
			expected: production,
		},
		{
			name: "virtual workspace with inherited version and renamed dependency",
			files: map[string]string{
				"Cargo.toml": `
[workspace]
members = ["./crates/*/"]
[workspace.package]
version = "1.0.0"
[workspace.dependencies]
alias = { package = "test-helper", version = "1" }
`,
				"crates/app/Cargo.toml": `
[package]
name = "app"
version.workspace = true
[dependencies]
runtime = "1"
[build-dependencies]
builder = "1"
[dev-dependencies]
alias.workspace = true
`,
			},
			expected: production,
		},
		{
			name: "another workspace member requires the test dependency for production",
			files: map[string]string{
				"Cargo.toml":                 "[workspace]\nmembers = [\"crates/*\"]\n",
				"crates/app/Cargo.toml":      devDependencyManifest,
				"crates/consumer/Cargo.toml": "[package]\nname = \"consumer\"\nversion = \"1.0.0\"\n[dependencies]\ntest-helper = \"1\"\n",
			},
			lock:     devDependencyLock + "\n[[package]]\nname = \"consumer\"\nversion = \"1.0.0\"\ndependencies = [\"test-helper\"]\n",
			expected: append(append([]string{}, all...), "consumer"),
		},
		{
			name:     "unrelated malformed manifest does not affect filtering",
			files:    map[string]string{"Cargo.toml": devDependencyManifest, "other/Cargo.toml": "[invalid"},
			expected: production,
		},
		{
			name: "local test-only path dependency",
			files: map[string]string{
				"Cargo.toml":                     strings.ReplaceAll(devDependencyManifest, `test-helper = "1"`, `test-helper = { path = "helpers/test-helper" }`),
				"helpers/test-helper/Cargo.toml": "[package]\nname = \"test-helper\"\nversion = \"1.0.0\"\n[dependencies]\nshared = \"1\"\ntest-leaf = \"1\"\n",
			},
			lock:     strings.Replace(devDependencyLock, "name = \"test-helper\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"", "name = \"test-helper\"\nversion = \"1.0.0\"", 1),
			expected: production,
		},
		{
			name:     "missing local test dependency manifest is retained conservatively",
			files:    map[string]string{"Cargo.toml": devDependencyManifest},
			lock:     strings.Replace(devDependencyLock, "name = \"test-helper\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"", "name = \"test-helper\"\nversion = \"1.0.0\"", 1),
			expected: all,
		},
		{
			name: "implicit workspace path member and its normal dependencies remain included",
			files: map[string]string{
				"Cargo.toml":                     localManifest + "\n[workspace]\n",
				"helpers/test-helper/Cargo.toml": localTestHelperManifest,
			},
			lock: localLock, expected: all,
		},
		{
			name: "workspace exclusion prevents implicit path membership",
			files: map[string]string{
				"Cargo.toml":                     localManifest + "\n[workspace]\nexclude = [\"helpers/*/\"]\n",
				"helpers/test-helper/Cargo.toml": localTestHelperManifest,
			},
			lock: localLock, expected: production,
		},
		{
			name: "path dependency owning another workspace is not an implicit member",
			files: map[string]string{
				"Cargo.toml":                     localManifest + "\n[workspace]\n",
				"helpers/test-helper/Cargo.toml": localTestHelperManifest + "\n[workspace]\n",
			},
			lock: localLock, expected: production,
		},
		{
			name: "ancestor workspace boundary prevents implicit path membership",
			files: map[string]string{
				"Cargo.toml":                     localManifest + "\n[workspace]\n",
				"helpers/Cargo.toml":             "[workspace]\nmembers = [\"test-helper\"]\n",
				"helpers/test-helper/Cargo.toml": localTestHelperManifest,
			},
			lock: localLock, expected: production,
		},
		{
			name: "path dependency outside workspace directory is not an implicit member",
			files: map[string]string{
				"project/Cargo.toml":             strings.Replace(localManifest, `path = "helpers/test-helper"`, `path = "../helpers/test-helper"`, 1) + "\n[workspace]\n",
				"helpers/test-helper/Cargo.toml": localTestHelperManifest,
			},
			lock: localLock, lockPath: "project/Cargo.lock", expected: production,
		},
		{
			name: "normal dependency takes precedence over development dependency",
			files: map[string]string{"Cargo.toml": devDependencyManifest + `
[target.'cfg(unix)'.dependencies]
test-helper = "1"
`},
			expected: all,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, content := range tt.files {
				filename := filepath.Join(dir, name)
				require.NoError(t, os.MkdirAll(filepath.Dir(filename), 0o755))
				require.NoError(t, os.WriteFile(filename, []byte(content), 0o600))
			}
			lock := tt.lock
			if lock == "" {
				lock = devDependencyLock
			}
			lockPath := tt.lockPath
			if lockPath == "" {
				lockPath = "Cargo.lock"
			}
			require.NoError(t, os.WriteFile(filepath.Join(dir, lockPath), []byte(lock), 0o600))
			cataloger := NewConfiguredCargoLockCataloger(DefaultCatalogerConfig().WithIncludeDevDependencies(tt.include))
			if tt.legacy {
				var factory func() pkg.Cataloger = NewCargoLockCataloger
				cataloger = factory()
			}
			pkgtest.NewCatalogTester().FromDirectory(t, dir).
				ExpectsAssertion(func(t *testing.T, packages []pkg.Package, relationships []artifact.Relationship) {
					var names []string
					ids := make(map[artifact.ID]bool)
					for _, p := range packages {
						names = append(names, p.Name)
						ids[p.ID()] = true
						if p.Name == "app" && len(tt.expected) == len(production) {
							assert.NotContains(t, p.Metadata.(pkg.RustCargoLockEntry).Dependencies, "test-helper")
						}
					}
					assert.ElementsMatch(t, tt.expected, names)
					for _, relationship := range relationships {
						assert.True(t, ids[relationship.From.ID()], "relationship source must be retained")
						assert.True(t, ids[relationship.To.ID()], "relationship target must be retained")
					}
				}).TestCataloger(t, cataloger)
		})
	}
}

func TestCargoDevDependenciesVersionedEdges(t *testing.T) {
	manifest, err := toml.Load(devDependencyManifest)
	require.NoError(t, err)
	entries := []pkg.RustCargoLockEntry{
		{Name: "app", Version: "1.0.0", Dependencies: []string{"runtime", "test-helper"}},
		{Name: "runtime", Version: "1.0.0", Source: "registry+example", Dependencies: []string{"shared 1.0.0"}},
		{Name: "test-helper", Version: "1.0.0", Source: "registry+example", Dependencies: []string{"shared 2.0.0"}},
		{Name: "shared", Version: "1.0.0", Source: "registry+example"},
		{Name: "shared", Version: "2.0.0", Source: "registry+example"},
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
	assert.ElementsMatch(t, []string{"app 1.0.0", "runtime 1.0.0", "shared 1.0.0"}, identities)
}

func TestCargoLockRuntimeReplacement(t *testing.T) {
	const manifest = `
[package]
name = "app"
version = "1.0.0"
[dependencies]
runtime = "1"
[dev-dependencies]
runtime-dev = { package = "runtime", git = "https://example.com/runtime.git" }
`
	const replacement = `
[replace]
"runtime:1.0.0" = { git = "https://example.com/runtime.git" }
`
	const lock = `
version = 3
[[package]]
name = "app"
version = "1.0.0"
dependencies = ["runtime 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)", "runtime 1.0.0 (git+https://example.com/runtime.git)"]
[[package]]
name = "runtime"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
replace = "runtime 1.0.0 (git+https://example.com/runtime.git)"
[[package]]
name = "runtime"
version = "1.0.0"
source = "git+https://example.com/runtime.git#abcd"
dependencies = ["runtime-leaf"]
[[package]]
name = "runtime-leaf"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`
	for _, workspace := range []bool{false, true} {
		name := "root package"
		files := map[string]string{"Cargo.toml": manifest + replacement, "Cargo.lock": lock}
		if workspace {
			name = "workspace member"
			files["Cargo.toml"] = "[workspace]\nmembers = [\"app\"]\n" + replacement
			files["app/Cargo.toml"] = manifest
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for filename, content := range files {
				filename = filepath.Join(dir, filename)
				require.NoError(t, os.MkdirAll(filepath.Dir(filename), 0o755))
				require.NoError(t, os.WriteFile(filename, []byte(content), 0o600))
			}
			pkgtest.NewCatalogTester().FromDirectory(t, dir).
				ExpectsAssertion(func(t *testing.T, packages []pkg.Package, relationships []artifact.Relationship) {
					var identities []string
					ids := make(map[artifact.ID]bool)
					for _, p := range packages {
						identities = append(identities, p.Name+" "+p.Metadata.(pkg.RustCargoLockEntry).Source)
						ids[p.ID()] = true
					}
					assert.Len(t, packages, 4)
					assert.Contains(t, identities, "runtime git+https://example.com/runtime.git#abcd")
					assert.Contains(t, identities, "runtime-leaf registry+https://github.com/rust-lang/crates.io-index")
					for _, relationship := range relationships {
						assert.True(t, ids[relationship.From.ID()])
						assert.True(t, ids[relationship.To.ID()])
					}
				}).TestCataloger(t, NewConfiguredCargoLockCataloger(DefaultCatalogerConfig().WithIncludeDevDependencies(false)))
		})
	}
}

func TestCargoManifestIdentity(t *testing.T) {
	tests := []struct {
		name      string
		manifest  string
		workspace string
		expected  string
	}{
		{"omitted version", "[package]\nname=\"app\"", "", "app 0.0.0"},
		{"explicit version", "[package]\nname=\"app\"\nversion=\"1.2.3\"", "", "app 1.2.3"},
		{"inherited version", "[package]\nname=\"app\"\nversion.workspace=true", "[workspace.package]\nversion=\"2.0.0\"", "app 2.0.0"},
		{"unresolved inheritance", "[package]\nname=\"app\"\nversion.workspace=true", "", ""},
		{"empty version", "[package]\nname=\"app\"\nversion=\"\"", "", ""},
		{"invalid version type", "[package]\nname=\"app\"\nversion=1", "", ""},
		{"virtual workspace", "[workspace]", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest, err := toml.Load(tt.manifest)
			require.NoError(t, err)
			workspace, err := toml.Load(tt.workspace)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, cargoManifestIdentity(manifest, workspace))
		})
	}
}
