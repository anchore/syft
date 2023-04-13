/*
Package golang provides a concrete Cataloger implementation for go.mod files.
*/
package golang

import (
	"os"
	"path"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/source"
	"github.com/mitchellh/go-homedir"
)

type GoCatalogerOpts struct {
	searchLocalModCacheLicenses bool
	localModCacheDir            string
	searchRemoteLicenses        bool
	proxy                       string
	noProxy                     []string
}

type goCatalogerOpt func(*GoCatalogerOpts)

func WithSearchLocalModCacheLicenses(input bool) goCatalogerOpt {
	return func(g *GoCatalogerOpts) {
		g.searchLocalModCacheLicenses = input
	}
}
func WithLocalModCacheDir(input string) goCatalogerOpt {
	return func(g *GoCatalogerOpts) {
		g.localModCacheDir = input
	}
}
func WithSearchRemoteLicenses(input bool) goCatalogerOpt {
	return func(g *GoCatalogerOpts) {
		g.searchRemoteLicenses = input
	}
}
func WithProxy(input string) goCatalogerOpt {
	return func(g *GoCatalogerOpts) {
		g.proxy = input
	}
}
func WithNoProxy(input string) goCatalogerOpt {
	return func(g *GoCatalogerOpts) {
		g.noProxy = strings.Split(input, ",")
	}
}

// NewGoCatalogerOpts create a GoCatalogerOpts given the input options, which includes
// pre-processing of the values. This includes:
// - setting the default remote proxy if none is provided
// - setting the default no proxy if none is provided
// - setting the default local module cache dir if none is provided
func NewGoCatalogerOpts(opts ...goCatalogerOpt) GoCatalogerOpts {
	g := GoCatalogerOpts{}
	for _, opt := range opts {
		opt(&g)
	}

	goPrivate := os.Getenv("GOPRIVATE")
	goNoProxy := os.Getenv("GONOPROXY")
	goProxy := os.Getenv("GOPROXY")

	// first process the proxy settings
	if g.proxy == "" {
		g.proxy = goProxy
	}
	if g.proxy == "off" {
		g.proxy = directProxyOnly
	}
	if g.proxy == "" {
		g.proxy = defaultRemoteProxies
	}

	// next process the gonoproxy settings
	// we only use the env var if it was not set explicitly
	if len(g.noProxy) == 0 && goNoProxy != "" {
		g.noProxy = append(g.noProxy, strings.Split(goNoProxy, ",")...)
	}

	// next process the goprivate settings; we always add those
	if goPrivate != "" {
		g.noProxy = append(g.noProxy, strings.Split(goPrivate, ",")...)
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

// NewGoModFileCataloger returns a new Go module cataloger object.
//
//nolint:revive
func NewGoModFileCataloger(opts GoCatalogerOpts) *progressingCataloger {
	c := goModCataloger{
		licenses: newGoLicenses(opts),
	}
	return &progressingCataloger{
		progress: c.licenses.progress,
		cataloger: generic.NewCataloger("go-mod-file-cataloger").
			WithParserByGlobs(c.parseGoModFile, "**/go.mod"),
	}
}

// NewGoModuleBinaryCataloger returns a new Golang cataloger object.
//
//nolint:revive
func NewGoModuleBinaryCataloger(opts GoCatalogerOpts) *progressingCataloger {
	c := goBinaryCataloger{
		licenses: newGoLicenses(opts),
	}
	return &progressingCataloger{
		progress: c.licenses.progress,
		cataloger: generic.NewCataloger("go-module-binary-cataloger").
			WithParserByMimeTypes(c.parseGoBinary, internal.ExecutableMIMETypeSet.List()...),
	}
}

type progressingCataloger struct {
	progress  *event.GenericProgress
	cataloger *generic.Cataloger
}

func (p *progressingCataloger) Name() string {
	return p.cataloger.Name()
}

func (p *progressingCataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
	defer p.progress.SetCompleted()
	return p.cataloger.Catalog(resolver)
}
