/*
A "one-stop-shop" for helper utilities for all major functionality provided by child packages of the syft library.

Here is what the main execution path for syft does:

	1. Parse a user image string to get a stereoscope image.Source object
	2. Invoke all catalogers to catalog the image, adding discovered packages to a single catalog object
	3. Invoke a single presenter to show the contents of the catalog

A Source object encapsulates the image object to be cataloged and the user options (catalog all layers vs. squashed layer),
providing a way to inspect paths and file content within the image. The Source object, not the image object, is used
throughout the main execution path. This abstraction allows for decoupling of what is cataloged (a docker image, an OCI
image, a filesystem, etc) and how it is cataloged (the individual catalogers).

Similar to the cataloging process, Linux distribution identification is also performed based on what is discovered within the image.
*/
package syft

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cataloger"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/logger"
	"github.com/anchore/syft/syft/pkg"
	jsonPresenter "github.com/anchore/syft/syft/presenter/json"
	"github.com/anchore/syft/syft/source"
	"github.com/wagoodman/go-partybus"
)

// Catalog the given image from a particular perspective (e.g. squashed source, all-layers source). Returns the discovered
// set of packages, the identified Linux distribution, and the source object used to wrap the data source.
func Catalog(userInput string, scope source.Scope) (source.Source, *pkg.Catalog, distro.Distro, error) {
	log.Info("cataloging image")
	s, cleanup, err := source.New(userInput, scope)
	defer cleanup()
	if err != nil {
		return source.Source{}, nil, distro.Distro{}, err
	}

	d := IdentifyDistro(s)

	catalog, err := CatalogFromScope(s)
	if err != nil {
		return source.Source{}, nil, distro.Distro{}, err
	}

	return s, catalog, d, nil
}

// IdentifyDistro attempts to discover what the underlying Linux distribution may be from the available flat files
// provided by the given source object. If results are inconclusive a "UnknownDistro" Type is returned.
func IdentifyDistro(s source.Source) distro.Distro {
	d := distro.Identify(s.Resolver)
	if d.Type != distro.UnknownDistroType {
		log.Infof("identified distro: %s", d.String())
	} else {
		log.Info("could not identify distro")
	}
	return d
}

// Catalog the given source, which may represent a container image or filesystem. Returns the discovered set of packages.
func CatalogFromScope(s source.Source) (*pkg.Catalog, error) {
	log.Info("building the catalog")

	// conditionally have two sets of catalogers
	var catalogers []cataloger.Cataloger
	switch s.Metadata.Scheme {
	case source.ImageScheme:
		catalogers = cataloger.ImageCatalogers()
	case source.DirectoryScheme:
		catalogers = cataloger.DirectoryCatalogers()
	default:
		return nil, fmt.Errorf("unable to determine cataloger set from scheme=%+v", s.Metadata.Scheme)
	}

	return cataloger.Catalog(s.Resolver, catalogers...)
}

// CatalogFromJSON takes an existing syft report and generates native syft objects.
func CatalogFromJSON(reader io.Reader) (source.Metadata, *pkg.Catalog, distro.Distro, error) {
	var doc jsonPresenter.Document
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&doc); err != nil {
		return source.Metadata{}, nil, distro.Distro{}, err
	}

	var pkgs = make([]pkg.Package, len(doc.Artifacts))
	for i, a := range doc.Artifacts {
		pkgs[i] = a.ToPackage()
	}

	catalog := pkg.NewCatalog(pkgs...)

	var distroType distro.Type
	if doc.Distro.Name == "" {
		distroType = distro.UnknownDistroType
	} else {
		distroType = distro.Type(doc.Distro.Name)
	}

	theDistro, err := distro.NewDistro(distroType, doc.Distro.Version, doc.Distro.IDLike)
	if err != nil {
		return source.Metadata{}, nil, distro.Distro{}, err
	}

	return doc.Source.ToSourceMetadata(), catalog, theDistro, nil
}

// SetLogger sets the logger object used for all syft logging calls.
func SetLogger(logger logger.Logger) {
	log.Log = logger
}

// SetBus sets the event bus for all syft library bus publish events onto (in-library subscriptions are not allowed).
func SetBus(b *partybus.Bus) {
	bus.SetPublisher(b)
}
