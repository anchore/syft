package python

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const eggInfoExtension = ".egg-info"

// NewPythonIndexCataloger returns a new cataloger for python packages referenced from poetry lock files, requirements.txt files, and setup.py files.
func NewPythonIndexCataloger() *generic.Cataloger {
	return generic.NewCataloger("python-index-cataloger").
		WithParser(parseRequirementsTxt, generic.NewSearch().ByBasenameGlob("*requirements*.txt").Request()).
		WithParserByBasename(parsePoetryLock, "poetry.lock").
		WithParserByBasename(parsePipfileLock, "Pipfile.lock").
		WithParserByBasename(parseSetup, "setup.py")
}

// NewPythonPackageCataloger returns a new cataloger for python packages within egg or wheel installation directories.
func NewPythonPackageCataloger() *generic.Cataloger {
	return generic.NewCataloger("python-package-cataloger").
		WithParser(parseWheelOrEgg,
			generic.NewSearch().ByBasename("METADATA").MustMatchGlob("**/*dist-info/METADATA"),
			generic.NewSearch().ByBasename("PKG-INFO").MustMatchGlob("**/*egg-info/PKG-INFO"),
		).
		WithParserByExtensions(parseWheelOrEgg,
			eggInfoExtension,
		)
}
