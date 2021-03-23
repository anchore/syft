/*
Package javascript provides a concrete Cataloger implementation for JavaScript ecosystem files (yarn and npm).
*/
package javascript

import (
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// NewJavascriptPackageCataloger returns a new JavaScript cataloger object based on detection of npm based packages.
func NewJavascriptPackageCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/package.json": parsePackageJSON,
	}

	return common.NewGenericCataloger(nil, globParsers, "javascript-package-cataloger")
}

// NewJavascriptLockCataloger returns a new Javascript cataloger object base on package lock files.
func NewJavascriptLockCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/package-lock.json": parsePackageLock,
		"**/yarn.lock":         parseYarnLock,
	}

	return common.NewGenericCataloger(nil, globParsers, "javascript-lock-cataloger")
}
