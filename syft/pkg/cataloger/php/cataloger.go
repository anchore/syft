/*
Package php provides a concrete Cataloger implementation for PHP ecosystem files.
*/
package php

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewPHPComposerInstalledCataloger returns a new cataloger for PHP installed.json files.
func NewPHPComposerInstalledCataloger() *generic.Cataloger {
	return generic.NewCataloger("php-composer-installed-cataloger").
		WithParserByBasename(parseInstalledJSON, "installed.json")
}

// NewPHPComposerLockCataloger returns a new cataloger for PHP composer.lock files.
func NewPHPComposerLockCataloger() *generic.Cataloger {
	return generic.NewCataloger("php-composer-lock-cataloger").
		WithParserByBasename(parseComposerLock, "composer.lock")
}
