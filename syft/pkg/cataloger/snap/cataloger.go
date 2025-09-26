/*
Package snap provides a concrete Cataloger implementation for snap packages, extracting metadata
from different types of snap files (base, kernel, system/gadget, snapd) rather than just scanning
the filesystem.
*/
package snap

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const catalogerName = "snap-cataloger"

// NewCataloger returns a new Snap cataloger object that can parse snap package metadata.
func NewCataloger() pkg.Cataloger {
	return generic.NewCataloger(catalogerName).
		// Look for snap.yaml to identify snap type and base snap info
		WithParserByGlobs(parseSnapYaml, "**/meta/snap.yaml").
		// Base snaps: dpkg.yaml files containing package manifests
		WithParserByGlobs(parseBaseDpkgYaml, "**/usr/share/snappy/dpkg.yaml").
		// Kernel snaps: changelog files for kernel version info
		WithParserByGlobs(parseKernelChangelog, "**/doc/linux-modules-*/changelog.Debian.gz").
		// System/Gadget snaps: manifest files with primed-stage-packages
		WithParserByGlobs(parseSystemManifest, "**/snap/manifest.yaml").
		// Snapd snaps: snapcraft.yaml files
		WithParserByGlobs(parseSnapdSnapcraft, "**/snap/snapcraft.yaml")
}
