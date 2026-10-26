package elixir

import (
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

var _ dependency.Specifier = mixLockDependencySpecifier

// mixLockDependencySpecifier declares that a mix.lock entry provides its own
// package name and requires the names listed in its dependency list, so the
// dependency processor can resolve dependency-of relationships between the
// locked packages.
func mixLockDependencySpecifier(p pkg.Package) dependency.Specification {
	meta, ok := p.Metadata.(pkg.ElixirMixLockEntry)
	if !ok {
		log.Tracef("cataloger failed to extract mix.lock metadata for package %+v", p.Name)
		return dependency.Specification{}
	}

	return dependency.Specification{
		ProvidesRequires: dependency.ProvidesRequires{
			Provides: []string{p.Name},
			Requires: meta.Dependencies,
		},
	}
}
