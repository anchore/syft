package dotnet

import (
	"context"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

const catalogerName = "dotnet-cataloger"

type CatalogerConfig struct {
	Option bool
}

type dotnetCataloger struct {
	cfg CatalogerConfig
}

func (d dotnetCataloger) Name() string {
	return catalogerName
}

func (d dotnetCataloger) Catalog(_ context.Context, _ file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	return nil, nil, nil
}
