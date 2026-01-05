package deno

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

func NewLockCataloger() pkg.Cataloger {
	return generic.NewCataloger("deno-lock-cataloger").
		WithParserByGlobs(parseDenoLock, "**/deno.lock")
}
