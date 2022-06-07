/*
Package python provides a concrete Cataloger implementation for Python ecosystem files (egg, wheel, requirements.txt).
*/
package python

import (
	"github.com/anchore/syft/syft/cataloger/packages/generic"
)

// NewPythonIndexCataloger returns a new cataloger for python packages referenced from poetry lock files, requirements.txt files, and setup.py files.
func NewPythonRequirementsCataloger() *generic.Cataloger {
	globParsers := map[string]generic.Parser{
		"**/*requirements*.txt": parseRequirementsTxt,
	}

	return generic.NewCataloger(nil, globParsers, "python-requirements-cataloger")
}

func NewPythonPoetryCataloger() *generic.Cataloger {
	globParsers := map[string]generic.Parser{
		"**/poetry.lock": parsePoetryLock,
	}

	return generic.NewCataloger(nil, globParsers, "python-poetry-cataloger")
}

func NewPythonPipfileCataloger() *generic.Cataloger {
	globParsers := map[string]generic.Parser{
		"**/Pipfile.lock": parsePipfileLock,
	}

	return generic.NewCataloger(nil, globParsers, "python-pipfile-cataloger")
}

func NewPythonSetupCataloger() *generic.Cataloger {
	globParsers := map[string]generic.Parser{
		"**/setup.py": parseSetup,
	}

	return generic.NewCataloger(nil, globParsers, "python-setup-cataloger")
}
