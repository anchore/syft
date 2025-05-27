package terraform

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

func NewLockCataloger() pkg.CatalogerWithRelease {
	return generic.NewCataloger("terraform-lock-cataloger").
		WithParserByGlobs(parseTerraformLock, "**/.terraform.lock.hcl")
}
