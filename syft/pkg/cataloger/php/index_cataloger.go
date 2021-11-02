/*
Package python provides a concrete Cataloger implementation for Python ecosystem files (egg, wheel, requirements.txt).
*/
package php

import (
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// NewPythonIndexCataloger returns a new cataloger for python packages referenced from poetry lock files, requirements.txt files, and setup.py files.
func NewPHPIndexCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/composer.lock": parseComposerLock,
	}

	return common.NewGenericCataloger(nil, globParsers, "php-index-cataloger")
}
