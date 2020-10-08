/*
Package python provides a concrete Cataloger implementation for Python ecosystem files (egg, wheel, requirements.txt).
*/
package python

import (
	"github.com/anchore/syft/syft/cataloger/common"
)

// NewPythonCataloger returns a new Python cataloger object.
func NewPythonCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/*egg-info/PKG-INFO":  parseEggMetadata,
		"**/*dist-info/METADATA": parseWheelMetadata,
		"**/*requirements*.txt":  parseRequirementsTxt,
		"**/poetry.lock":         parsePoetryLock,
		"**/setup.py":            parseSetup,
	}

	return common.NewGenericCataloger(nil, globParsers, "python-cataloger")
}
