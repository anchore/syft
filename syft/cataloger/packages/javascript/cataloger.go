/*
Package javascript provides a concrete Cataloger implementation for JavaScript ecosystem files (yarn and npm).
*/
package javascript

import (
	"github.com/anchore/syft/syft/cataloger/packages/generic"
)

// NewJavascriptPackageCataloger returns a new JavaScript cataloger object based on detection of npm based packages.
func NewJavascriptPackageCataloger() *generic.Cataloger {
	globParsers := map[string]generic.Parser{
		"**/package.json": parsePackageJSON,
	}

	return generic.NewCataloger(nil, globParsers, "javascript-package-json-cataloger")
}

// NewJavascriptLockCataloger returns a new Javascript cataloger object base on package lock files.
func NewJavascriptPackageLockCataloger() *generic.Cataloger {
	globParsers := map[string]generic.Parser{
		"**/package-lock.json": parsePackageLock,
	}

	return generic.NewCataloger(nil, globParsers, "javascript-package-lock-cataloger")
}

func NewJavascriptYarnLockCataloger() *generic.Cataloger {
	globParsers := map[string]generic.Parser{
		"**/yarn.lock": parseYarnLock,
	}

	return generic.NewCataloger(nil, globParsers, "javascript-yarn-lock-cataloger")
}
