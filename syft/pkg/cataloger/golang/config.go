package golang

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/go-homedir"
	"github.com/anchore/syft/internal/log"
)

const (
	defaultProxies  = "https://proxy.golang.org,direct"
	directProxyOnly = "direct"
)

var (
	directProxiesOnly = []string{directProxyOnly}
)

type CatalogerConfig struct {
	SearchLocalModCacheLicenses bool                    `yaml:"search-local-mod-cache-licenses" json:"search-local-mod-cache-licenses" mapstructure:"search-local-mod-cache-licenses"`
	LocalModCacheDir            string                  `yaml:"local-mod-cache-dir" json:"local-mod-cache-dir" mapstructure:"local-mod-cache-dir"`
	SearchLocalVendorLicenses   bool                    `yaml:"search-local-vendor-licenses" json:"search-local-vendor-licenses" mapstructure:"search-local-vendor-licenses"`
	LocalVendorDir              string                  `yaml:"local-vendor-dir" json:"local-vendor-dir" mapstructure:"local-vendor-dir"`
	SearchRemoteLicenses        bool                    `yaml:"search-remote-licenses" json:"search-remote-licenses" mapstructure:"search-remote-licenses"`
	Proxies                     []string                `yaml:"proxies,omitempty" json:"proxies,omitempty" mapstructure:"proxies"`
	NoProxy                     []string                `yaml:"no-proxy,omitempty" json:"no-proxy,omitempty" mapstructure:"no-proxy"`
	MainModuleVersion           MainModuleVersionConfig `yaml:"main-module-version" json:"main-module-version" mapstructure:"main-module-version"`
	GoSourceConfig              GoSourceConfig          `yaml:"go-source-config" json:"go-source-config" mapstructure:"go-source-config"`
}

type GoSourceConfig struct {
	IncludeTests bool `yaml:"include-tests" json:"include-tests" mapstructure:"include-tests"`
	// Dir is the directory in which to run the go build system's query tool
	// that provides information about the packages.
	// If Dir is empty, the tool is run in the current directory.
	Dir         string   `yaml:"dir" json:"dir" mapstructure:"dir"`
	ImportPaths []string `yaml:"import-paths" json:"import-paths" mapstructure:"import-paths"`
	IgnorePaths []string `yaml:"ignore-paths" json:"ignore-paths" mapstructure:"ignore-paths"`
	// true, we continue searching a branch even if dep ignored; good for license search and package exclusion
	// false, we cut the ignored path's branch off and skip all sub packages
	IncludeIgnoredDeps bool `yaml:"include-ignored-deps" json:"include-ignored-deps" mapstructure:"include-ignored-deps"`
}

type MainModuleVersionConfig struct {
	FromLDFlags       bool `yaml:"from-ld-flags" json:"from-ld-flags" mapstructure:"from-ld-flags"`
	FromContents      bool `yaml:"from-contents" json:"from-contents" mapstructure:"from-contents"`
	FromBuildSettings bool `yaml:"from-build-settings" json:"from-build-settings" mapstructure:"from-build-settings"`
}

// DefaultCatalogerConfig create a CatalogerConfig with default options, which includes:
// - setting the default remote proxy if none is provided
// - setting the default no proxy if none is provided
// - setting the default local module cache dir if none is provided
func DefaultCatalogerConfig() CatalogerConfig {
	g := CatalogerConfig{
		MainModuleVersion: DefaultMainModuleVersionConfig(),
		LocalModCacheDir:  defaultGoModDir(),
		GoSourceConfig:    defaultGoSourceConfig(),
	}

	// first process the proxy settings
	if len(g.Proxies) == 0 {
		goProxy := os.Getenv("GOPROXY")
		if goProxy == "" {
			goProxy = defaultProxies
		}
		g = g.WithProxy(goProxy)
	}

	// next process the gonoproxy settings
	if len(g.NoProxy) == 0 {
		goPrivate := os.Getenv("GOPRIVATE")
		goNoProxy := os.Getenv("GONOPROXY")
		// we only use the env var if it was not set explicitly
		if goPrivate != "" {
			g.NoProxy = append(g.NoProxy, strings.Split(goPrivate, ",")...)
		}

		// next process the goprivate settings; we always add those
		if goNoProxy != "" {
			g.NoProxy = append(g.NoProxy, strings.Split(goNoProxy, ",")...)
		}
	}

	return g
}

// defaultGoModDir returns $GOPATH/pkg/mod or $HOME/go/pkg/mod based on environment variables available
func defaultGoModDir() string {
	goPath := os.Getenv("GOPATH")

	if goPath == "" {
		homeDir, err := homedir.Dir()
		if err != nil {
			log.Debugf("unable to determine GOPATH or user home dir: %w", err)
			return ""
		}
		goPath = filepath.Join(homeDir, "go")
	}

	return filepath.Join(goPath, "pkg", "mod")
}

func defaultGoSourceConfig() GoSourceConfig {
	return GoSourceConfig{
		IncludeTests:       false,
		ImportPaths:        []string{"./..."},
		IncludeIgnoredDeps: false,
	}
}

func DefaultMainModuleVersionConfig() MainModuleVersionConfig {
	return MainModuleVersionConfig{
		FromLDFlags:       true,
		FromContents:      false,
		FromBuildSettings: true,
	}
}

func (g CatalogerConfig) WithIncludeTests(includeTests bool) CatalogerConfig {
	g.GoSourceConfig.IncludeTests = includeTests
	return g
}

func (g CatalogerConfig) WithSourceDir(dir string) CatalogerConfig {
	g.GoSourceConfig.Dir = dir
	return g
}

func (g CatalogerConfig) WithImportPaths(importPaths []string) CatalogerConfig {
	// by default, we tell the Go libraries to recursively include all packages in the source directory
	// and it's subdirectories. If the user provides this by config or env we drop this default and use their options
	if len(importPaths) == 0 {
		return g
	}
	g.GoSourceConfig.ImportPaths = importPaths
	return g
}

func (g CatalogerConfig) WithIgnorePaths(ignorePaths []string) CatalogerConfig {
	g.GoSourceConfig.IgnorePaths = append(g.GoSourceConfig.IgnorePaths, ignorePaths...)
	return g
}

func (g CatalogerConfig) WithIncludeIgnoreDeps(includeIgnoreDeps bool) CatalogerConfig {
	g.GoSourceConfig.IncludeIgnoredDeps = includeIgnoreDeps
	return g
}

func (g CatalogerConfig) WithSearchLocalModCacheLicenses(input bool) CatalogerConfig {
	g.SearchLocalModCacheLicenses = input
	return g
}

func (g CatalogerConfig) WithLocalModCacheDir(input string) CatalogerConfig {
	if input == "" {
		return g
	}
	g.LocalModCacheDir = input
	return g
}

func (g CatalogerConfig) WithSearchLocalVendorLicenses(input bool) CatalogerConfig {
	g.SearchLocalVendorLicenses = input
	return g
}

func (g CatalogerConfig) WithLocalVendorDir(input string) CatalogerConfig {
	if input == "" {
		return g
	}
	g.LocalVendorDir = input
	return g
}

func (g CatalogerConfig) WithSearchRemoteLicenses(input bool) CatalogerConfig {
	g.SearchRemoteLicenses = input
	return g
}

func (g CatalogerConfig) WithProxy(input string) CatalogerConfig {
	if input == "" {
		return g
	}
	if input == "off" {
		input = directProxyOnly
	}
	g.Proxies = strings.Split(input, ",")
	return g
}

func (g CatalogerConfig) WithNoProxy(input string) CatalogerConfig {
	if input == "" {
		return g
	}
	g.NoProxy = strings.Split(input, ",")
	return g
}

func (g CatalogerConfig) WithMainModuleVersion(input MainModuleVersionConfig) CatalogerConfig {
	g.MainModuleVersion = input
	return g
}

func (g MainModuleVersionConfig) WithFromLDFlags(input bool) MainModuleVersionConfig {
	g.FromLDFlags = input
	return g
}

func (g MainModuleVersionConfig) WithFromContents(input bool) MainModuleVersionConfig {
	g.FromContents = input
	return g
}

func (g MainModuleVersionConfig) WithFromBuildSettings(input bool) MainModuleVersionConfig {
	g.FromBuildSettings = input
	return g
}
