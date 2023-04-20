package generic

import (
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

type Environment struct {
	LinuxRelease *linux.Release
}

type Parser func(file.Resolver, *Environment, source.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error)
