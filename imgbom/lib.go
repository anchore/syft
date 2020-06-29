package imgbom

import (
	"github.com/anchore/imgbom/imgbom/cataloger"
	"github.com/anchore/imgbom/imgbom/distro"
	"github.com/anchore/imgbom/imgbom/logger"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/imgbom/scope"
	"github.com/anchore/imgbom/internal/bus"
	"github.com/anchore/imgbom/internal/log"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/wagoodman/go-partybus"
)

func IdentifyDistro(img *image.Image) *distro.Distro {
	return distro.Identify(img)
}

func CatalogDir(d string, o scope.Option) (*pkg.Catalog, error) {
	s, err := scope.NewDirScope(d, o)
	if err != nil {
		return nil, err
	}
	return cataloger.Catalog(s)
}

func CatalogImg(img *image.Image, o scope.Option) (*pkg.Catalog, error) {
	s, err := scope.NewImageScope(img, o)
	if err != nil {
		return nil, err
	}
	return cataloger.Catalog(s)
}

func SetLogger(logger logger.Logger) {
	log.Log = logger
}

func SetBus(b *partybus.Bus) {
	bus.SetPublisher(b)
}
