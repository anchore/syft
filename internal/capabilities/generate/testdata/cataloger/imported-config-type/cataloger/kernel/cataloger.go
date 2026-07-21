package kernel

import (
	"context"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

func NewLinuxKernelCataloger(_ LinuxKernelCatalogerConfig) pkg.Cataloger {
	return generic.NewCataloger("linux-kernel-cataloger").
		WithParserByGlobs(parse, "**/vmlinuz")
}

func parse(_ context.Context, _ file.Resolver, _ *generic.Environment, _ file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	return nil, nil, nil
}
