package javascript

import (
	"fmt"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

func packageLockDependencySpecifier(p pkg.Package) dependency.Specification {
	meta, ok := p.Metadata.(pkg.NpmPackageLockEntry)
	if !ok {
		log.Tracef("cataloger failed to extract package lock metadata for package %+v", p.Name)
		return dependency.Specification{}
	}

	provides := []string{p.Name}

	var requires []string

	for name, dependencySpecifier := range meta.Dependencies {
		purl, err := packageurl.FromString(strings.ReplaceAll(dependencySpecifier, "npm:", "pkg:npm/"))
		if err == nil {
			// if the package url is valid, include the name from the package url since this is likely an alias
			var fullName = fmt.Sprintf("%s/%s", purl.Namespace, purl.Name)
			requires = append(requires, fullName)
		} else {
			fmt.Println("error", err)
		}

		requires = append(requires, name)
	}

	return dependency.Specification{
		ProvidesRequires: dependency.ProvidesRequires{
			Provides: provides,
			Requires: requires,
		},
	}
}

func pnpmLockDependencySpecifier(p pkg.Package) dependency.Specification {
	meta, ok := p.Metadata.(pkg.PnpmLockEntry)
	if !ok {
		log.Tracef("cataloger failed to extract pnpm lock metadata for package %+v", p.Name)
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

func yarnLockDependencySpecifier(p pkg.Package) dependency.Specification {
	meta, ok := p.Metadata.(pkg.YarnLockEntry)
	if !ok {
		log.Tracef("cataloger failed to extract yarn lock metadata for package %+v", p.Name)
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
