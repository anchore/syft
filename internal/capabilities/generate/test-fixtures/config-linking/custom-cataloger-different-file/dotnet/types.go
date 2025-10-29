package dotnet

import (
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

func (d dotnetCataloger) Catalog(resolver any) ([]pkg.Package, []pkg.Relationship, error) {
	return nil, nil, nil
}
