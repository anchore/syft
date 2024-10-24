package terraform

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

func NewTerraformCataloger() pkg.Cataloger {
	return generic.NewCataloger("terraform-cataloger").
		WithParserByGlobs(parseTerraformLock, "**/.terraform.lock.hcl").
		WithProcessors()
}
