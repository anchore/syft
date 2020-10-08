/*
Package javascript provides a concrete Cataloger implementation for JavaScript ecosystem files (yarn and npm).
*/
package javascript

import (
	"github.com/anchore/syft/syft/cataloger/common"
)

// NewJavascriptCataloger returns a new JavaScript cataloger object.
func NewJavascriptCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/package-lock.json": parsePackageLock,
		"**/yarn.lock":         parseYarnLock,
	}

	return common.NewGenericCataloger(nil, globParsers, "javascript-cataloger")
}
