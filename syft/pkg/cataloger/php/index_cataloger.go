/*
Package php provides a concrete Cataloger implementation for PHP ecosystem files.
*/
package php

import (
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// NewPhPInstalledCataloger returns a new cataloger for PHP installed.json files.
func NewPhPInstalledCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/installed.json": parseInstalledJson,
	}

	return common.NewGenericCataloger(nil, globParsers, "php-installed-cataloger")
}

// NewPHPIndexCataloger returns a new cataloger for PHP composer.lock files.
func NewPHPIndexCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/composer.lock": parseComposerLock,
	}

	return common.NewGenericCataloger(nil, globParsers, "php-index-cataloger")
}
