package imgbom

import (
	"github.com/anchore/imgbom/imgbom/cataloger"
	"github.com/anchore/imgbom/imgbom/distro"
	"github.com/anchore/imgbom/imgbom/logger"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/imgbom/scope"
	"github.com/anchore/imgbom/internal/bus"
	"github.com/anchore/imgbom/internal/log"
	"github.com/wagoodman/go-partybus"
)

func Catalog(userInput string, scoptOpt scope.Option) (*pkg.Catalog, *scope.Scope, *distro.Distro, error) {
	s, cleanup, err := scope.NewScope(userInput, scoptOpt)
	defer cleanup()
	if err != nil {
		return nil, nil, nil, err
	}

	d := IdentifyDistro(s)

	catalog, err := CatalogFromScope(s)
	if err != nil {
		return nil, nil, nil, err
	}

	return catalog, &s, &d, nil
}

func IdentifyDistro(s scope.Scope) distro.Distro {
	d := distro.Identify(s)
	if d.Type != distro.UnknownDistroType {
		log.Infof("Identified Distro: %s", d.String())
	} else {
		log.Info("Could not identify distro")
	}
	return d
}

func CatalogFromScope(s scope.Scope) (*pkg.Catalog, error) {
	log.Info("Building the Catalog")
	return cataloger.Catalog(s)
}

func SetLogger(logger logger.Logger) {
	log.Log = logger
}

func SetBus(b *partybus.Bus) {
	bus.SetPublisher(b)
}
