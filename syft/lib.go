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

	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/syft/cpe"

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

// LoadCPEDictionary retrieve the index used
func LoadCPEDictionary(cfg config.CPEDictionary) (cpe.Dictionary, error) {
	dictionaryCurator := cpe.NewCurator(cfg)

	if cfg.AutoUpdate {
		_, err := dictionaryCurator.Update()
		if err != nil {
			return nil, err
		}
	}

	store, err := dictionaryCurator.GetDictionary()
	if err != nil {
		return nil, err
	}

	return store, nil
}

// Catalog the given image from a particular perspective (e.g. squashed source, all-layers source). Returns the discovered
// set of packages, the identified Linux distribution, and the source object used to wrap the data source.
func Catalog(userInput string, cpeDictionary cpe.Dictionary, scope source.Scope) (source.Source, *pkg.Catalog, *distro.Distro, error) {
	theSource, cleanup, err := source.New(userInput, scope)
	defer cleanup()
	if err != nil {
		return source.Source{}, nil, nil, err
	}

	// find the distro
	theDistro := distro.Identify(theSource.Resolver)
	if theDistro != nil {
		log.Infof("identified distro: %s", theDistro.String())
	} else {
		log.Info("could not identify distro")
	}

	// conditionally use the correct set of loggers based on the input type (container image or directory)
	var catalogers []cataloger.Cataloger
	switch theSource.Metadata.Scheme {
	case source.ImageScheme:
		log.Info("cataloging image")
		catalogers = cataloger.ImageCatalogers()
	case source.DirectoryScheme:
		log.Info("cataloging directory")
		catalogers = cataloger.DirectoryCatalogers()
	default:
		return source.Source{}, nil, nil, fmt.Errorf("unable to determine cataloger set from scheme=%+v", theSource.Metadata.Scheme)
	}

	catalog, err := cataloger.Catalog(theSource.Resolver, cpeDictionary, theDistro, catalogers...)
	if err != nil {
		return source.Source{}, nil, nil, err
	}

	return theSource, catalog, theDistro, nil
}

// CatalogFromJSON takes an existing syft report and generates native syft objects.
func CatalogFromJSON(reader io.Reader) (source.Metadata, *pkg.Catalog, *distro.Distro, error) {
	var doc jsonPresenter.Document
	var err error
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&doc); err != nil {
		return source.Metadata{}, nil, nil, err
	}

	var pkgs = make([]pkg.Package, len(doc.Artifacts))
	for i, a := range doc.Artifacts {
		pkgs[i], err = a.ToPackage()
		if err != nil {
			return source.Metadata{}, nil, nil, err
		}
	}

	catalog := pkg.NewCatalog(pkgs...)

	var theDistro *distro.Distro
	if doc.Distro.Name != "" {
		d, err := distro.NewDistro(distro.Type(doc.Distro.Name), doc.Distro.Version, doc.Distro.IDLike)
		if err != nil {
			return source.Metadata{}, nil, nil, err
		}
		theDistro = &d
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
