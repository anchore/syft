/*
Package python provides a concrete Cataloger implementation for Python ecosystem files (egg, wheel, requirements.txt).
*/
package python

import (
	"github.com/anchore/syft/syft/cataloger/packages/generic"
)

// NewPythonIndexCataloger returns a new cataloger for python packages referenced from poetry lock files, requirements.txt files, and setup.py files.
func NewPythonIndexCataloger() *generic.Cataloger {
	globParsers := map[string]generic.Parser{
		"**/*requirements*.txt": parseRequirementsTxt,
		"**/poetry.lock":        parsePoetryLock,
		"**/Pipfile.lock":       parsePipfileLock,
		"**/setup.py":           parseSetup,
	}

	return generic.NewCataloger(nil, globParsers, "python-index-cataloger")
}
