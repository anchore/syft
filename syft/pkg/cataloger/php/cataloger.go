/*
Package php provides a concrete Cataloger implementation relating to packages within the PHP language ecosystem.
*/
package php

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// Note about the distinction between composer.lock and installed.json: composer.lock and installed.json have different
// semantic meanings. The lock file represents what should be installed, whereas the installed file represents what is installed.

// NewComposerInstalledCataloger returns a new cataloger for PHP installed.json files.
func NewComposerInstalledCataloger() pkg.Cataloger {
	return generic.NewCataloger("php-composer-installed-cataloger").
		WithParserByGlobs(parseInstalledJSON, "**/installed.json")
}

// NewComposerLockCataloger returns a new cataloger for PHP composer.lock files.
func NewComposerLockCataloger() pkg.Cataloger {
	return generic.NewCataloger("php-composer-lock-cataloger").
		WithParserByGlobs(parseComposerLock, "**/composer.lock")
}

// NewPearCataloger returns a new cataloger for PHP Pear metadata (including Pecl metadata).
func NewPearCataloger() pkg.Cataloger {
	return generic.NewCataloger("php-pear-serialized-cataloger").
		WithParserByGlobs(parsePear, "**/php/.registry/**/*.reg")
}

// NewPeclCataloger returns a new cataloger for PHP Pecl metadata. Note: this will also catalog Pear metadata so should
// not be used in conjunction with the Pear Cataloger.
// Deprecated: please use NewPearCataloger instead.
func NewPeclCataloger() pkg.Cataloger {
	return generic.NewCataloger("php-pecl-serialized-cataloger").
		WithParserByGlobs(parsePecl, "**/php/.registry/.channel.*/*.reg")
}
