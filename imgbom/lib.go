package imgbom

import (
	"fmt"

	"github.com/anchore/imgbom/imgbom/cataloger"
	"github.com/anchore/imgbom/imgbom/distro"
	"github.com/anchore/imgbom/imgbom/logger"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/imgbom/scope"
	"github.com/anchore/imgbom/internal/bus"
	"github.com/anchore/imgbom/internal/log"
	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/wagoodman/go-partybus"
)

func IdentifyDistro(s scope.Scope) *distro.Distro {
	return distro.Identify(s)
}

// NewScope produces a Scope based on userInput like dir:// or image:tag
func NewScope(userInput string, o scope.Option) (scope.Scope, func(), error) {
	protocol := NewProtocol(userInput)
	log.Debugf("protocol: %+v", protocol)

	switch protocol.Type {
	case DirProtocol:
		// populate the scope object for dir
		s, err := GetScopeFromDir(protocol.Value, o)
		if err != nil {
			return scope.Scope{}, func() {}, fmt.Errorf("could not populate scope from path (%s): %w", protocol.Value, err)
		}
		return s, func() {}, nil

	case ImageProtocol:
		log.Infof("Fetching image '%s'", userInput)
		img, err := stereoscope.GetImage(userInput)
		cleanup := func() {
			stereoscope.Cleanup()
		}

		if err != nil || img == nil {
			return scope.Scope{}, cleanup, fmt.Errorf("could not fetch image '%s': %w", userInput, err)
		}

		s, err := GetScopeFromImage(img, o)
		if err != nil {
			return scope.Scope{}, cleanup, fmt.Errorf("could not populate scope with image: %w", err)
		}
		return s, cleanup, nil

	default:
		return scope.Scope{}, func() {}, fmt.Errorf("unable to process input for scanning: '%s'", userInput)
	}
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
