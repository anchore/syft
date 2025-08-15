/*
Package python provides a concrete Cataloger implementation relating to packages within the Python language ecosystem.
*/
package python

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const eggInfoGlob = "**/*.egg-info"

type CatalogerConfig struct {
	GuessUnpinnedRequirements bool `yaml:"guess-unpinned-requirements" json:"guess-unpinned-requirements" mapstructure:"guess-unpinned-requirements"`
}

func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{
		GuessUnpinnedRequirements: false,
	}
}

// NewPackageCataloger returns a new cataloger for python packages referenced from poetry lock files, requirements.txt files, and setup.py files.
func NewPackageCataloger(cfg CatalogerConfig) pkg.Cataloger {
	rqp := newRequirementsParser(cfg)
	return generic.NewCataloger("python-package-cataloger").
		WithParserByGlobs(rqp.parseRequirementsTxt, "**/*requirements*.txt").
		WithParserByGlobs(parsePoetryLock, "**/poetry.lock").
		WithParserByGlobs(parsePipfileLock, "**/Pipfile.lock").
		WithParserByGlobs(parseSetup, "**/setup.py").
		WithParserByGlobs(parseUvLock, "**/uv.lock")
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
