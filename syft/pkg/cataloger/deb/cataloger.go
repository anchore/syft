/*
Package dpkg provides a concrete Cataloger implementation for Debian package DB status files.
*/
package deb

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const catalogerName = "dpkgdb-cataloger"

// NewDpkgdbCataloger returns a new Deb package cataloger capable of parsing DPKG status DB files.
func NewDpkgdbCataloger() *generic.Cataloger {
	return generic.NewCataloger(catalogerName).
		// TODO: split up and re-write the glob search patterns
		WithParserByGlobs(parseDpkgDB, pkg.DpkgDBGlob)
}
