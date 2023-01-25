/*
Package portage provides a concrete Cataloger implementation for Gentoo Portage.
*/
package portage

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

func NewPortageCataloger() *generic.Cataloger {
	return generic.NewCataloger("portage-cataloger").
		WithParser(parsePortageContents, generic.NewSearch().ByBasename("CONTENTS").MustMatchGlob("**/var/db/pkg/*/*/CONTENTS"))
}
