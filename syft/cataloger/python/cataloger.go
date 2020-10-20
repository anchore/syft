/*
Package python provides a concrete Cataloger implementation for Python ecosystem files (egg, wheel, requirements.txt).
*/
package python

import (
	"github.com/anchore/syft/syft/cataloger/common"
)

// NewPythonPackageCataloger returns a new cataloger for python packages within egg or wheel installation directories.
func NewPythonPackageCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/*egg-info/PKG-INFO":  parseWheelOrEggMetadata,
		"**/*dist-info/METADATA": parseWheelOrEggMetadata,
	}

	return common.NewGenericCataloger(nil, globParsers, "python-package-cataloger")
}

// NewPythonIndexCataloger returns a new cataloger for python packages referenced from poetry lock files, requirements.txt files, and setup.py files.
func NewPythonIndexCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/*requirements*.txt": parseRequirementsTxt,
		"**/poetry.lock":        parsePoetryLock,
		"**/setup.py":           parseSetup,
	}

	return common.NewGenericCataloger(nil, globParsers, "python-index-cataloger")
}
