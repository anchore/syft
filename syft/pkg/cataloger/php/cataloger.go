/*
Package php provides a concrete Cataloger implementation for PHP ecosystem files.
*/
package php

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewPHPComposerInstalledCataloger returns a new cataloger for PHP installed.json files.
func NewPHPComposerInstalledCataloger() *generic.Cataloger {
	globParsers := map[string]generic.Parser{
		"**/installed.json": parseInstalledJSON,
	}

	return generic.NewCataloger(nil, globParsers, "php-composer-installed-cataloger")
}

// NewPHPComposerLockCataloger returns a new cataloger for PHP composer.lock files.
func NewPHPComposerLockCataloger() *generic.Cataloger {
	globParsers := map[string]generic.Parser{
		"**/composer.lock": parseComposerLock,
	}

	return generic.NewCataloger(nil, globParsers, "php-composer-lock-cataloger")
}
