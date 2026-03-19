package bun

import (
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

func bunLockDependencySpecifier(p pkg.Package) dependency.Specification {
	meta, ok := p.Metadata.(pkg.BunLockEntry)
	if !ok {
		log.Tracef("bun lock: no metadata for %s", p.Name)
		return dependency.Specification{}
	}

	provides := []string{p.Name}

	var requires []string
	for name := range meta.Dependencies {
		requires = append(requires, name)
	}

	return dependency.Specification{
		ProvidesRequires: dependency.ProvidesRequires{
			Provides: provides,
			Requires: requires,
		},
	}
}
