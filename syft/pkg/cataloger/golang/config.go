package golang

import (
	"os"
	"path"
	"strings"

	"github.com/mitchellh/go-homedir"

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
	SearchLocalModCacheLicenses bool     `yaml:"search-local-mod-cache-licenses" json:"search-local-mod-cache-licenses" mapstructure:"search-local-mod-cache-licenses"`
	LocalModCacheDir            string   `yaml:"local-mod-cache-dir" json:"local-mod-cache-dir" mapstructure:"local-mod-cache-dir"`
	SearchRemoteLicenses        bool     `yaml:"search-remote-licenses" json:"search-remote-licenses" mapstructure:"search-remote-licenses"`
	Proxies                     []string `yaml:"proxies,omitempty" json:"proxies,omitempty" mapstructure:"proxies"`
	NoProxy                     []string `yaml:"no-proxy,omitempty" json:"no-proxy,omitempty" mapstructure:"no-proxy"`
}

// DefaultCatalogerConfig create a CatalogerConfig with default options, which includes:
// - setting the default remote proxy if none is provided
// - setting the default no proxy if none is provided
// - setting the default local module cache dir if none is provided
func DefaultCatalogerConfig() CatalogerConfig {
	g := CatalogerConfig{}

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

	if g.LocalModCacheDir == "" {
		goPath := os.Getenv("GOPATH")

		if goPath == "" {
			homeDir, err := homedir.Dir()
			if err != nil {
				log.Debug("unable to determine user home dir: %v", err)
			} else {
				goPath = path.Join(homeDir, "go")
			}
		}
		if goPath != "" {
			g.LocalModCacheDir = path.Join(goPath, "pkg", "mod")
		}
	}
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
