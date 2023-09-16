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
		WithParserByGlobs(parsePackageJSON, "**/package.json")
}

// NewLockCataloger returns a new JavaScript cataloger object based on detection of lock files.
func NewLockCataloger() *generic.Cataloger {
	return generic.NewCataloger("javascript-lock-cataloger").
		WithParserByGlobs(parsePackageLock, "**/package-lock.json").
		WithParserByGlobs(parseYarnLock, "**/yarn.lock").
		WithParserByGlobs(parsePnpmLock, "**/pnpm-lock.yaml")
}

// NewJavaScriptCataloger returns a new JavaScript cataloger object based on detection
// of npm based packages and lock files to provide a complete dependency graph of the
// packages.
func NewJavaScriptCataloger() *generic.GroupedCataloger {
	return generic.NewGroupedCataloger("javascript-cataloger").
		WithParserByGlobColocation(parseJavaScript, "**/yarn.lock", []string{"**/package.json", "**/yarn.lock"}).
		WithParserByGlobColocation(parseJavaScript, "**/package-lock.json", []string{"**/package.json", "**/package-lock.json"}).
		WithParserByGlobColocation(parseJavaScript, "**/pnpm-lock.yaml", []string{"**/package.json", "**/pnpm-lock.yaml"})
}
