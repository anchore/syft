package terraform

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

func NewLockCataloger(cfg CatalogerConfig) pkg.Cataloger {
	lr := newTerraformLicenseResolver(cfg)
	return generic.NewCataloger("terraform-lock-cataloger").
		WithParserByGlobs(lr.parseTerraformLock, "**/.terraform.lock.hcl")
}
