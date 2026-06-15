/*
Package python provides a concrete Cataloger implementation relating to packages within the Python language ecosystem.
*/
package python

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const eggInfoGlob = "**/*.egg-info"

// NewPackageCataloger returns a new cataloger for python packages referenced from poetry lock files, requirements.txt files, and setup.py files.
func NewPackageCataloger(cfg CatalogerConfig) pkg.Cataloger {
	poetryLockParser := newPoetryLockParser(cfg)
	pipfileLockParser := newPipfileLockParser(cfg)
	setupFileParser := newSetupFileParser(cfg)
	uvLockParser := newUvLockParser(cfg)
	pdmLockParser := newPdmLockParser(cfg)
	requirementsFileParser := newRequirementsParser(cfg)
	return generic.NewCataloger("python-package-cataloger").
		WithParserByGlobs(requirementsFileParser.parseRequirementsTxt, "**/*requirements*.txt").
		WithParserByGlobs(poetryLockParser.parsePoetryLock, "**/poetry.lock").
		WithParserByGlobs(pipfileLockParser.parsePipfileLock, "**/Pipfile.lock").
		WithParserByGlobs(setupFileParser.parseSetupFile, "**/setup.py").
		// uv lock files are named "uv.lock", but PEP 723 script lock files
		// (created by "uv lock --script <name>.py") are named "<name>.py.lock"
		// and use the same format, so catalog both.
		WithParserByGlobs(uvLockParser.parseUvLock, "**/uv.lock", "**/*.py.lock").
		WithParserByGlobs(pdmLockParser.parsePdmLock, "**/pdm.lock")
}

// NewInstalledPackageCataloger returns a new cataloger for python packages within egg or wheel installation directories.
func NewInstalledPackageCataloger() pkg.Cataloger {
	return generic.NewCataloger("python-installed-package-cataloger").
		WithParserByGlobs(
			parseWheelOrEgg,
			eggInfoGlob,
			"**/*dist-info/METADATA",
			"**/*egg-info/PKG-INFO",
			"**/*DIST-INFO/METADATA",
			"**/*EGG-INFO/PKG-INFO",
		).WithResolvingProcessors(wheelEggRelationships)
}
