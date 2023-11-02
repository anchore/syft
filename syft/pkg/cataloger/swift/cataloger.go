/*
Package swift provides a concrete Cataloger implementation relating to packages within the swift language ecosystem.
*/
package swift

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

func NewSwiftPackageManagerCataloger() *generic.Cataloger {
	return generic.NewCataloger("swift-package-manager-cataloger").
		WithParserByGlobs(parsePackageResolved, "**/Package.resolved", "**/.package.resolved")
}

// NewCocoapodsCataloger returns a new Swift Cocoapods lock file cataloger object.
func NewCocoapodsCataloger() *generic.Cataloger {
	return generic.NewCataloger("cocoapods-cataloger").
		WithParserByGlobs(parsePodfileLock, "**/Podfile.lock")
}
