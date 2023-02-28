/*
Package golang provides a concrete Cataloger implementation for go.mod files.
*/
package golang

import (
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type GoCatalogerOpts struct {
	SearchLocalModCacheLicenses bool
	SearchRemoteLicenses        bool
	LocalModCacheDir            string
	RemoteProxy                 string
}

// NewGoModFileCataloger returns a new Go module cataloger object.
func NewGoModFileCataloger(opts GoCatalogerOpts) *generic.Cataloger {
	c := goModCataloger{
		licenses: newGoLicenses(opts),
	}
	return generic.NewCataloger("go-mod-file-cataloger").
		WithParserByGlobs(c.parseGoModFile, "**/go.mod")
}

// NewGoModuleBinaryCataloger returns a new Golang cataloger object.
func NewGoModuleBinaryCataloger(opts GoCatalogerOpts) *generic.Cataloger {
	c := goBinaryCataloger{
		licenses: newGoLicenses(opts),
	}
	return generic.NewCataloger("go-module-binary-cataloger").
		WithParserByMimeTypes(c.parseGoBinary, internal.ExecutableMIMETypeSet.List()...)
}
