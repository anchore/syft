/*
Package static_binary provides a concrete Cataloger implementation for x/applcation mimetypes compiled with gcc
*/
package static_binary

import (
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

func NewStaticBinaryPackageCataloger(opts StaticBinaryCatalogerOpts) pkg.Cataloger {
	c := staticBinaryCataloger{
		licenses: newStaticLicenses(opts),
	}
	return &progressingCataloger{
		progress: c.licenses.progress,
		cataloger: generic.NewCataloger("static-binary-file-cataloger").
			WithParserByMimeTypes(c.parseStaticBinary, internal.ExecutableMIMETypeSet.List()...),
	}
}

func NewStaticBinaryPackageLibCataloger(opts StaticBinaryCatalogerOpts) pkg.Cataloger {
	c := staticBinaryLibCataloger{
		licenses: newStaticLicenses(opts),
	}
	return &progressingCataloger{
		progress: c.licenses.progress,
		cataloger: generic.NewCataloger("static-binary-lib-cataloger").
			WithParserByGlobs(c.parseStaticBinaryLib, "**/lib*.so"),
	}
}

func DefaultCatalogerConfig() StaticBinaryCatalogerOpts {
	return NewStaticBinaryCatalogerOpts()
}

type progressingCataloger struct {
	progress  *monitor.CatalogerTask
	cataloger *generic.Cataloger
}

func (p *progressingCataloger) Name() string {
	return p.cataloger.Name()
}

func (p *progressingCataloger) Catalog(resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	defer p.progress.SetCompleted()
	return p.cataloger.Catalog(resolver)
}
