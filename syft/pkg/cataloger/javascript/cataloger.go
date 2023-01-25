/*
Package javascript provides a concrete Cataloger implementation for JavaScript ecosystem files (yarn and npm).
*/
package javascript

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewPackageCataloger returns a new JavaScript cataloger object based on detection of npm based packages.
func NewPackageCataloger() *generic.Cataloger {
	return generic.NewCataloger("javascript-package-cataloger").
		WithParserByBasename(parsePackageJSON, "package.json")
}

// NewLockCataloger returns a new JavaScript cataloger object based on detection of lock files.
func NewLockCataloger() *generic.Cataloger {
	return generic.NewCataloger("javascript-lock-cataloger").
		WithParserByBasename(parsePackageLock, "package-lock.json").
		WithParserByBasename(parseYarnLock, "yarn.lock").
		WithParserByBasename(parsePnpmLock, "pnpm-lock.yaml")
}
