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
	// SearchLocalModCacheLicenses enables searching for go package licenses in the local GOPATH mod cache.
	// app-config: golang.search-local-mod-cache-licenses
	SearchLocalModCacheLicenses bool `yaml:"search-local-mod-cache-licenses" json:"search-local-mod-cache-licenses" mapstructure:"search-local-mod-cache-licenses"`

	// LocalModCacheDir specifies the location of the local go module cache directory. When not set, syft will attempt to discover the GOPATH env or default to $HOME/go.
	// app-config: golang.local-mod-cache-dir
	LocalModCacheDir string `yaml:"local-mod-cache-dir" json:"local-mod-cache-dir" mapstructure:"local-mod-cache-dir"`

	// SearchLocalVendorLicenses enables searching for go package licenses in the local vendor directory relative to the go.mod file.
	// app-config: golang.search-local-vendor-licenses
	SearchLocalVendorLicenses bool `yaml:"search-local-vendor-licenses" json:"search-local-vendor-licenses" mapstructure:"search-local-vendor-licenses"`

	// LocalVendorDir specifies the location of the local vendor directory. When not set, syft will search for a vendor directory relative to the go.mod file.
	// app-config: golang.local-vendor-dir
	LocalVendorDir string `yaml:"local-vendor-dir" json:"local-vendor-dir" mapstructure:"local-vendor-dir"`

	// SearchRemoteLicenses enables downloading go package licenses from the upstream go proxy (typically proxy.golang.org).
	// app-config: golang.search-remote-licenses
	SearchRemoteLicenses bool `yaml:"search-remote-licenses" json:"search-remote-licenses" mapstructure:"search-remote-licenses"`

	// Proxies is a list of go module proxies to use when fetching go module metadata and licenses. When not set, syft will use the GOPROXY env or default to https://proxy.golang.org,direct.
	// app-config: golang.proxy
	Proxies []string `yaml:"proxies,omitempty" json:"proxies,omitempty" mapstructure:"proxies"`

	// NoProxy is a list of glob patterns that match go module names that should not be fetched from the go proxy. When not set, syft will use the GOPRIVATE and GONOPROXY env vars.
	// app-config: golang.no-proxy
	NoProxy []string `yaml:"no-proxy,omitempty" json:"no-proxy,omitempty" mapstructure:"no-proxy"`

	MainModuleVersion MainModuleVersionConfig `yaml:"main-module-version" json:"main-module-version" mapstructure:"main-module-version"`
}

type MainModuleVersionConfig struct {
	// FromLDFlags enables parsing the main module version from the -ldflags build settings.
	// app-config: golang.main-module-version.from-ld-flags
	FromLDFlags bool `yaml:"from-ld-flags" json:"from-ld-flags" mapstructure:"from-ld-flags"`

	// FromContents enables parsing the main module version from the binary contents. This is useful when the version is embedded in the binary but not in the build settings.
	// app-config: golang.main-module-version.from-contents
	FromContents bool `yaml:"from-contents" json:"from-contents" mapstructure:"from-contents"`

	// FromBuildSettings enables parsing the main module version from the go build settings.
	// app-config: golang.main-module-version.from-build-settings
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

func DefaultMainModuleVersionConfig() MainModuleVersionConfig {
	return MainModuleVersionConfig{
		FromLDFlags:       true,
		FromContents:      false,
		FromBuildSettings: true,
	}
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
