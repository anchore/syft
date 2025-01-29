package golang

import (
	"context"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type goModSourceCataloger struct {
	licenseResolver goLicenseResolver
}

func newGoModSourceCataloger(opts CatalogerConfig) *goModSourceCataloger {
	return &goModSourceCataloger{
		licenseResolver: newGoLicenseResolver(sourceFileCatalogerName, opts),
	}
}

func (c *goModSourceCataloger) parseGoModFile(ctx context.Context, _ file.Resolver, _ *generic.Environment, _ file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	return []pkg.Package{}, []artifact.Relationship{}, nil
}
