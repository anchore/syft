/*
A "one-stop-shop" for helper utilities for all major functionality provided by child packages of the syft library.

Here is what the main execution path for syft does:

	1. Parse a user image string to get a stereoscope image.Source object
	2. Invoke all catalogers to catalog the image, adding discovered packages to a single catalog object
	3. Invoke a single presenter to show the contents of the catalog

A Scope object encapsulates the image object to be cataloged and the user options (catalog all layers vs. squashed layer),
providing a way to inspect paths and file content within the image. The Scope object, not the image object, is used
throughout the main execution path. This abstraction allows for decoupling of what is cataloged (a docker image, an OCI
image, a filesystem, etc) and how it is cataloged (the individual catalogers).

Similar to the cataloging process, Linux distribution identification is also performed based on what is discovered within the image.
*/
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

// Catalog the given image from a particular perspective (e.g. squashed scope, all-layers scope). Returns the discovered
// set of packages, the identified Linux distribution, and the scope object used to wrap the data source.
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

// IdentifyDistro attempts to discover what the underlying Linux distribution may be from the available flat files
// provided by the given scope object. If results are inconclusive a "UnknownDistro" Type is returned.
func IdentifyDistro(s scope.Scope) distro.Distro {
	d := distro.Identify(s.Resolver)
	if d.Type != distro.UnknownDistroType {
		log.Infof("identified distro: %s", d.String())
	} else {
		log.Info("could not identify distro")
	}
	return d
}

// Catalog the given scope, which may represent a container image or filesystem. Returns the discovered set of packages.
func CatalogFromScope(s scope.Scope) (*pkg.Catalog, error) {
	log.Info("building the catalog")

	// conditionally have two sets of catalogers
	//var catalogers []cataloger.Cataloger
	//// if image
	//// use one set of catalogers
	//catalogers = ...
	//
	//// if dir
	//// use another set of catalogers

	return cataloger.Catalog(s.Resolver, cataloger.All()...)
}

// SetLogger sets the logger object used for all syft logging calls.
func SetLogger(logger logger.Logger) {
	log.Log = logger
}

// SetBus sets the event bus for all syft library bus publish events onto (in-library subscriptions are not allowed).
func SetBus(b *partybus.Bus) {
	bus.SetPublisher(b)
}
