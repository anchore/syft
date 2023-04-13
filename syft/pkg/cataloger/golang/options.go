package golang

import (
	"os"
	"path"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/mitchellh/go-homedir"
)

const (
	defaultProxies  = "https://proxy.golang.org,direct"
	directProxyOnly = "direct"
)

var (
	directProxiesOnly = []string{directProxyOnly}
)

type GoCatalogerOpts struct {
	searchLocalModCacheLicenses bool
	localModCacheDir            string
	searchRemoteLicenses        bool
	proxies                     []string
	noProxy                     []string
}

type GoCatalogerOpt func(*GoCatalogerOpts)

func (g GoCatalogerOpts) WithSearchLocalModCacheLicenses(input bool) GoCatalogerOpts {
	g.searchLocalModCacheLicenses = input
	return g
}

func (g GoCatalogerOpts) WithLocalModCacheDir(input string) GoCatalogerOpts {
	g.localModCacheDir = input
	return g
}

func (g GoCatalogerOpts) WithSearchRemoteLicenses(input bool) GoCatalogerOpts {
	g.searchRemoteLicenses = input
	return g
}

func (g GoCatalogerOpts) WithProxy(input string) GoCatalogerOpts {
	if input == "off" {
		input = directProxyOnly
	}
	if input == "" {
		g.proxies = nil
	} else {
		g.proxies = strings.Split(input, ",")
	}

	g2 := g.updateProxies()
	return g2
}

func (g GoCatalogerOpts) WithNoProxy(input string) GoCatalogerOpts {
	if input == "" {
		g.noProxy = nil
	} else {
		g.noProxy = strings.Split(input, ",")
	}
	g.updateProxies()
	g2 := g.updateProxies()
	return g2
}

func (g GoCatalogerOpts) updateProxies() GoCatalogerOpts {
	// first process the proxy settings
	if len(g.proxies) == 0 {
		goProxy := os.Getenv("GOPROXY")
		if goProxy == "" {
			goProxy = defaultProxies
		}
		g = g.WithProxy(goProxy)
	}

	// next process the gonoproxy settings
	if len(g.noProxy) == 0 {
		goPrivate := os.Getenv("GOPRIVATE")
		goNoProxy := os.Getenv("GONOPROXY")
		// we only use the env var if it was not set explicitly
		if goPrivate != "" {
			g.noProxy = append(g.noProxy, strings.Split(goPrivate, ",")...)
		}

		// next process the goprivate settings; we always add those
		if goNoProxy != "" {
			g.noProxy = append(g.noProxy, strings.Split(goNoProxy, ",")...)
		}
	}

	if g.localModCacheDir == "" {
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
			g.localModCacheDir = path.Join(goPath, "pkg", "mod")
		}
	}
	return g
}

// NewGoCatalogerOpts create a GoCatalogerOpts with default options, which includes:
// - setting the default remote proxy if none is provided
// - setting the default no proxy if none is provided
// - setting the default local module cache dir if none is provided
func NewGoCatalogerOpts() GoCatalogerOpts {
	return GoCatalogerOpts{}
}
