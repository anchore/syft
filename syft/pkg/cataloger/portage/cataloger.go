/*
Package portage provides a concrete Cataloger implementation for Gentoo Portage.
*/
package portage

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewPortageCataloger returns a new cataloger object initialized for Gentoo Portage package manager files (a flat-file store).
func NewPortageCataloger() *generic.Cataloger {
	return generic.NewCataloger("portage-cataloger").
		WithParserByGlobs(parsePortageContents, "**/var/db/pkg/*/*/CONTENTS")
}
