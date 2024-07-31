/*
Package swipl provides a Cataloger implementation relating to packages within the SWI Prolog language ecosystem.
*/
package swipl

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewSwiplPackCataloger returns a new SWI Prolog Pack package manager cataloger object.
func NewSwiplPackCataloger() pkg.Cataloger {
	return generic.NewCataloger("swipl-pack-cataloger").
		WithParserByGlobs(parsePackPackage, "**/pack.pl")
}
