/*
Package javascript provides a concrete Cataloger implementation for packages relating to the JavaScript language ecosystem.
*/
package javascript

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewPackageCataloger returns a new cataloger object for NPM.
func NewPackageCataloger() pkg.Cataloger {
	return NewPackageCatalogerWithConfig(DefaultCatalogerConfig())
}

// NewPackageCatalogerWithConfig returns an NPM package cataloger with the given configuration.
func NewPackageCatalogerWithConfig(cfg CatalogerConfig) pkg.Cataloger {
	parser := packageJSONParser{cfg: cfg}
	return generic.NewCataloger("javascript-package-cataloger").
		WithParserByGlobs(parser.parsePackageJSON, "**/package.json")
}

// NewLockCataloger returns a new cataloger object for NPM (and NPM-adjacent, such as yarn) lock files.
func NewLockCataloger(cfg CatalogerConfig) pkg.Cataloger {
	yarnLockAdapter := newGenericYarnLockAdapter(cfg)
	packageLockAdapter := newGenericPackageLockAdapter(cfg)
	pnpmLockAdapter := newGenericPnpmLockAdapter(cfg)
	bunLockAdapter := newGenericBunLockAdapter(cfg)
	denoLockAdapter := newGenericDenoLockAdapter(cfg)
	return generic.NewCataloger("javascript-lock-cataloger").
		WithParserByGlobs(packageLockAdapter.parsePackageLock, "**/package-lock.json").
		WithParserByGlobs(yarnLockAdapter.parseYarnLock, "**/yarn.lock").
		WithParserByGlobs(pnpmLockAdapter.parsePnpmLock, "**/pnpm-lock.yaml").
		WithParserByGlobs(bunLockAdapter.parseBunLock, "**/bun.lock").
		WithParserByGlobs(denoLockAdapter.parseDenoLock, "**/deno.lock")
}
