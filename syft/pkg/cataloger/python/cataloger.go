package python

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const (
	eggMetadataGlob     = "**/*egg-info/PKG-INFO"
	eggFileMetadataGlob = "**/*.egg-info"
	wheelMetadataGlob   = "**/*dist-info/METADATA"
)

// NewPythonIndexCataloger returns a new cataloger for python packages referenced from poetry lock files, requirements.txt files, and setup.py files.
func NewPythonIndexCataloger() *generic.Cataloger {
	return generic.NewCataloger("python-index-cataloger").
		WithParserByGlobs(parseRequirementsTxt, "**/*requirements*.txt").
		WithParserByGlobs(parsePoetryLock, "**/poetry.lock").
		WithParserByGlobs(parsePipfileLock, "**/Pipfile.lock").
		WithParserByGlobs(parseSetup, "**/setup.py")
}

// NewPythonPackageCataloger returns a new cataloger for python packages within egg or wheel installation directories.
func NewPythonPackageCataloger() *generic.Cataloger {
	return generic.NewCataloger("python-package-cataloger").
		WithParserByGlobs(parseWheelOrEgg, eggMetadataGlob, eggFileMetadataGlob, wheelMetadataGlob)
}
