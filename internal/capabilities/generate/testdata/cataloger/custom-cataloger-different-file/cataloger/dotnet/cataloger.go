package dotnet

import (
	"github.com/anchore/syft/syft/pkg"
)

func NewDotnetCataloger(cfg CatalogerConfig) pkg.Cataloger {
	return dotnetCataloger{cfg: cfg}
}
