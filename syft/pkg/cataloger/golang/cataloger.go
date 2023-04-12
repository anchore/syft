/*
Package golang provides a concrete Cataloger implementation for go.mod files.
*/
package golang

import (
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/source"
)

type GoCatalogerOpts struct {
	SearchLocalModCacheLicenses bool
	LocalModCacheDir            string
	SearchRemoteLicenses        bool
	Proxy                       string
	NoProxy                     string
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
