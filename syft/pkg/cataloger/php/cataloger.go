/*
Package php provides a concrete Cataloger implementation for PHP ecosystem files.
*/
package php

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewComposerInstalledCataloger returns a new cataloger for PHP installed.json files.
func NewComposerInstalledCataloger() *generic.Cataloger {
	return generic.NewCataloger("php-composer-installed-cataloger").
		WithParserByGlobs(parseInstalledJSON, "**/installed.json")
}

// NewComposerLockCataloger returns a new cataloger for PHP composer.lock files.
func NewComposerLockCataloger() *generic.Cataloger {
	return generic.NewCataloger("php-composer-lock-cataloger").
		WithParserByGlobs(parseComposerLock, "**/composer.lock")
}
