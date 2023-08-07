/*
Package swift provides a concrete Cataloger implementation for Podfile.lock and Package.resolved files.
*/
package swift

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

func NewSwiftPackageManagerCataloger() *generic.Cataloger {
	return generic.NewCataloger("spm-cataloger").
		WithParserByGlobs(parsePackageResolved, "**/Package.resolved", "**/.package.resolved")
}

// NewCocoapodsCataloger returns a new Swift Cocoapods lock file cataloger object.
func NewCocoapodsCataloger() *generic.Cataloger {
	return generic.NewCataloger("cocoapods-cataloger").
		WithParserByGlobs(parsePodfileLock, "**/Podfile.lock")
}
