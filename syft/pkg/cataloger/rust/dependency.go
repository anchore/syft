package rust

import (
	"fmt"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

func cargoLockDependencySpecifier(p pkg.Package) dependency.Specification {
	meta, ok := p.Metadata.(pkg.RustCargo)
	if !ok {
		log.Tracef("cataloger failed to extract rust cargo metadata for package %+v", p.Name)
		return dependency.Specification{}
	}

	if meta.LockEntry == nil {
		log.Tracef("cataloger failed to extract rust cargo lock entry for package %+v", p.Name)
		return dependency.Specification{}
	}

	provides := []string{p.Name, p.Name + "@" + p.Version}

	var requires []string
	for _, depSpecifier := range meta.LockEntry.Dependencies {
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

func splitPackageChoice(s string) (ret []string) {
	name, versionString, found := strings.Cut(s, " ")
	if found {
		ret = append(ret, fmt.Sprintf("%s@%s", name, versionString))
	} else {
		ret = append(ret, name)
	}
	return ret
}
