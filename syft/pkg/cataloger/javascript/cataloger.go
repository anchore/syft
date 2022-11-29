/*
Package javascript provides a concrete Cataloger implementation for JavaScript ecosystem files (yarn and npm).
*/
package javascript

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewJavascriptPackageCataloger returns a new JavaScript cataloger object based on detection of npm based packages.
func NewJavascriptPackageCataloger() *generic.Cataloger {
	return generic.NewCataloger("javascript-package-cataloger").
		WithParserByGlobs(parsePackageJSON, "**/package.json")
}

func NewJavascriptLockCataloger() *generic.Cataloger {
	return generic.NewCataloger("javascript-lock-cataloger").
		WithParserByGlobs(parsePackageLock, "**/package-lock.json").
		WithParserByGlobs(parseYarnLock, "**/yarn.lock").
		WithParserByGlobs(parsePnpmLock, "**/pnpm-lock.yaml")
}
