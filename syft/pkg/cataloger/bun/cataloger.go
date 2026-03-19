package bun

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

func NewLockCataloger() pkg.Cataloger {
	return generic.NewCataloger("bun-lock-cataloger").
		WithParserByGlobs(parseBunLock, "**/bun.lock").
		WithProcessors(dependency.Processor(bunLockDependencySpecifier))
}
