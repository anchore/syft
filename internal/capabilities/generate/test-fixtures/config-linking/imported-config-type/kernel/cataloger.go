package kernel

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

func NewLinuxKernelCataloger(cfg LinuxKernelCatalogerConfig) pkg.Cataloger {
	return generic.NewCataloger("linux-kernel-cataloger").
		WithParserByGlobs(parse, "**/vmlinuz")
}

func parse(path string, reader any) ([]pkg.Package, []pkg.Relationship, error) {
	return nil, nil, nil
}
