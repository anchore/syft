package debian

import (
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

var _ dependency.Specifier = dbEntryDependencySpecifier

func dbEntryDependencySpecifier(p pkg.Package) dependency.Specification {
	meta, ok := p.Metadata.(pkg.DpkgDBEntry)
	if !ok {
		log.Tracef("cataloger failed to extract dpkg metadata for package %+v", p.Name)
		return dependency.Specification{}
	}
	provides := []string{p.Name}
	for _, key := range meta.Provides {
		if key == "" {
			continue
		}
		provides = append(provides, stripVersionSpecifier(key))
	}

	var allDeps []string
	allDeps = append(allDeps, meta.Depends...)
	allDeps = append(allDeps, meta.PreDepends...)

	var requires []string
	for _, depSpecifier := range allDeps {
		if depSpecifier == "" {
			continue
		}
		requires = append(requires, splitPackageChoice(depSpecifier)...)
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
	// libgmp10 (>= 2:6.2.1+dfsg1)         -->  libgmp10
	// libgmp10                            -->  libgmp10
	// foo [i386]                          -->  foo
	// default-mta | mail-transport-agent  -->  default-mta | mail-transport-agent
	// kernel-headers-2.2.10 [!hurd-i386]  -->  kernel-headers-2.2.10

	return strings.TrimSpace(internal.SplitAny(s, "[(<>=")[0])
}

func splitPackageChoice(s string) (ret []string) {
	fields := strings.Split(s, "|")
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" {
			ret = append(ret, stripVersionSpecifier(field))
		}
	}
	return ret
}
