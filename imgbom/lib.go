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

func IdentifyDistro(s scope.Scope) *distro.Distro {
	return distro.Identify(s)
}

func GetScopeFromDir(d string, o scope.Option) (scope.Scope, error) {
	return scope.NewScopeFromDir(d, o)
}

func GetScopeFromImage(img *image.Image, o scope.Option) (scope.Scope, error) {
	return scope.NewScopeFromImage(img, o)
}

func Catalog(s scope.Scope) (*pkg.Catalog, error) {
	return cataloger.Catalog(s)
}

func SetLogger(logger logger.Logger) {
	log.Log = logger
}

func SetBus(b *partybus.Bus) {
	bus.SetPublisher(b)
}
