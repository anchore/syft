/*
Package deb provides a concrete Cataloger implementation for Debian package DB status files.
*/
package deb

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const catalogerName = "dpkgdb-cataloger"

// NewDpkgdbCataloger returns a new Deb package cataloger capable of parsing DPKG status DB files.
func NewDpkgdbCataloger() *generic.Cataloger {
	return generic.NewCataloger(catalogerName).
		// note: these globs have been intentionally split up in order to improve search performance,
		// please do NOT combine into: "**/var/lib/dpkg/{status,status.d/*}"
		WithParserByGlobs(parseDpkgDB, "**/var/lib/dpkg/status", "**/var/lib/dpkg/status.d/*", "**/lib/opkg/info/*.control", "**/lib/opkg/status")
}
