package arch

import (
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

var _ dependency.Specifier = dbEntryDependencySpecifier

func dbEntryDependencySpecifier(p pkg.Package) dependency.Specification {
	meta, ok := p.Metadata.(pkg.AlpmDBEntry)
	if !ok {
		log.Tracef("cataloger failed to extract alpm metadata for package %+v", p.Name)
		return dependency.Specification{}
	}

	provides := []string{p.Name}
	for _, key := range meta.Provides {
		if key == "" {
			continue
		}
		provides = append(provides, key, stripVersionSpecifier(key))
	}

	var requires []string
	for _, depSpecifier := range meta.Depends {
		if depSpecifier == "" {
			continue
		}
		requires = append(requires, depSpecifier)
	}

	return dependency.Specification{
		ProvidesRequires: dependency.ProvidesRequires{
			Provides: provides,
			Requires: requires,
		},
	}
}

func stripVersionSpecifier(s string) string {
	// examples:
	// gcc-libs                  -->  gcc-libs
	// libtree-sitter.so=0-64    -->  libtree-sitter.so

	return strings.TrimSpace(strings.Split(s, "=")[0])
}
