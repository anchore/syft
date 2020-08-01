package syft

import (
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cataloger"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/logger"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
	"github.com/wagoodman/go-partybus"
)

func Catalog(userInput string, scoptOpt scope.Option) (*pkg.Catalog, *scope.Scope, *distro.Distro, error) {
	log.Info("cataloging image")
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
		log.Infof("identified distro: %s", d.String())
	} else {
		log.Info("could not identify distro")
	}
	return d
}

func CatalogFromScope(s scope.Scope) (*pkg.Catalog, error) {
	log.Info("building the catalog")
	return cataloger.Catalog(s)
}

func SetLogger(logger logger.Logger) {
	log.Log = logger
}

func SetBus(b *partybus.Bus) {
	bus.SetPublisher(b)
}
