/*
Package hadron provides a cataloger for Hadron Linux, which records installed
component versions in a single flat JSON file at /usr/lib/hadron/components.json.
*/
package hadron

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewCataloger returns a cataloger for the Hadron components.json inventory file.
func NewCataloger() pkg.Cataloger {
	return generic.NewCataloger("hadron-cataloger").
		WithParserByGlobs(parseComponents, "**/usr/lib/hadron/components.json")
}
