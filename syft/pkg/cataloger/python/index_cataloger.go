/*
Package python provides a concrete Cataloger implementation for Python ecosystem files (egg, wheel, requirements.txt).
*/
package python

import (
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// NewPythonIndexCataloger returns a new cataloger for python packages referenced from poetry lock files, requirements.txt files, and setup.py files.
func NewPythonIndexCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/*requirements*.txt": parseRequirementsTxt,
		"**/poetry.lock":        parsePoetryLock,
		"**/Pipfile.lock":       parsePipfileLock,
		"**/setup.py":           parseSetup,
	}

	return common.NewGenericCataloger(nil, globParsers, "python-index-cataloger")
}
