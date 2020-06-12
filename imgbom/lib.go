package imgbom

import (
	"github.com/anchore/imgbom/imgbom/analyzer"
	"github.com/anchore/imgbom/imgbom/distro"
	"github.com/anchore/imgbom/imgbom/logger"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/imgbom/scope"
	"github.com/anchore/imgbom/internal/log"
	"github.com/anchore/stereoscope/pkg/image"
)

func IdentifyDistro(img *image.Image) *distro.Distro {
	return distro.Identify(img)
}

func CatalogImage(img *image.Image, o scope.Option) (*pkg.Catalog, error) {
	s, err := scope.NewScope(img, o)
	if err != nil {
		return nil, err
	}

	return analyzer.Analyze(s)
}

func SetLogger(logger logger.Logger) {
	log.Log = logger
}
