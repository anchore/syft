package ruby

import (
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

var _ dependency.Specifier = gemfileLockDependencySpecifier

// gemfileLockDependencySpecifier declares that a Gemfile.lock entry provides its
// own gem name and requires the names listed in its dependency list, so
// dependency.Resolve can build dependency-of relationships between the gems
// locked in the same file.
func gemfileLockDependencySpecifier(p pkg.Package) dependency.Specification {
	meta, ok := p.Metadata.(pkg.RubyGemfileLockEntry)
	if !ok {
		log.Tracef("cataloger failed to extract Gemfile.lock metadata for package %+v", p.Name)
		return dependency.Specification{}
	}

	return dependency.Specification{
		ProvidesRequires: dependency.ProvidesRequires{
			Provides: []string{p.Name},
			Requires: meta.Dependencies,
		},
	}
}
