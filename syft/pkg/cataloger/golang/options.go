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

type GoCatalogerOpts struct {
	searchLocalModCacheLicenses bool
	localModCacheDir            string
	searchRemoteLicenses        bool
	proxies                     []string
	noProxy                     []string
}

type GoCatalogerOpt func(*GoCatalogerOpts)

func WithSearchLocalModCacheLicenses(input bool) GoCatalogerOpt {
	return func(g *GoCatalogerOpts) {
		g.searchLocalModCacheLicenses = input
	}
}

func WithLocalModCacheDir(input string) GoCatalogerOpt {
	return func(g *GoCatalogerOpts) {
		g.localModCacheDir = input
	}
}

func WithSearchRemoteLicenses(input bool) GoCatalogerOpt {
	return func(g *GoCatalogerOpts) {
		g.searchRemoteLicenses = input
	}
}

func WithProxy(input string) GoCatalogerOpt {
	return func(g *GoCatalogerOpts) {
		if input == "" {
			return
		}
		if input == "off" {
			input = directProxyOnly
		}
		g.proxies = strings.Split(input, ",")
	}
}

func WithNoProxy(input string) GoCatalogerOpt {
	return func(g *GoCatalogerOpts) {
		if input == "" {
			return
		}
		g.noProxy = strings.Split(input, ",")
	}
}

// NewGoCatalogerOpts create a GoCatalogerOpts with default options, which includes:
// - setting the default remote proxy if none is provided
// - setting the default no proxy if none is provided
// - setting the default local module cache dir if none is provided
func NewGoCatalogerOpts(opts ...GoCatalogerOpt) GoCatalogerOpts {
	g := GoCatalogerOpts{}
	for _, opt := range opts {
		opt(&g)
	}

	// first process the proxy settings
	if len(g.proxies) == 0 {
		goProxy := os.Getenv("GOPROXY")
		if goProxy == "" {
			goProxy = defaultProxies
		}
		WithProxy(goProxy)(&g)
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
