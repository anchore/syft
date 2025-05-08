/*
Package syft is a "one-stop-shop" for helper utilities for all major functionality provided by child packages of the syft library.

Here is what the main execution path for syft does:

 1. Parse a user image string to get a stereoscope image.Source object
 2. Invoke all catalogers to catalog the image, adding discovered packages to a single catalog object
 3. Invoke one or more encoders to output contents of the catalog

A Source object encapsulates the image object to be cataloged and the user options (catalog all layers vs. squashed layer),
providing a way to inspect paths and file content within the image. The Source object, not the image object, is used
throughout the main execution path. This abstraction allows for decoupling of what is cataloged (a docker image, an OCI
image, a filesystem, etc) and how it is cataloged (the individual catalogers).

Similar to the cataloging process, Linux distribution identification is also performed based on what is discovered within the image.
*/
package syft

import (
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/go-logger"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
)

// SetLogger sets the logger object used for all syft logging calls.
func SetLogger(logger logger.Logger) {
	log.Set(logger)
}

// SetBus sets the event bus for all syft library bus publish events onto (in-library subscriptions are not allowed).
func SetBus(b *partybus.Bus) {
	bus.Set(b)
}
