package redhat

import (
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

var _ dependency.Specifier = dbEntryDependencySpecifier

func dbEntryDependencySpecifier(p pkg.Package) dependency.Specification {
	meta, ok := p.Metadata.(pkg.RpmDBEntry)
	if !ok {
		log.Tracef("cataloger failed to extract rpmdb metadata for package %+v", p.Name)
		return dependency.Specification{}
	}

	provides := []string{p.Name}
	for _, key := range meta.Provides {
		if key == "" {
			continue
		}
		if !isSupportedKey(key) {
			continue
		}
		provides = append(provides, key)
	}

	// all owned files are also considered "provides" for the package
	for _, f := range meta.Files {
		provides = append(provides, f.Path)
	}

	var requires []string
	for _, key := range meta.Requires {
		if key == "" {
			continue
		}
		if !isSupportedKey(key) {
			continue
		}
		requires = append(requires, key)
	}

	return dependency.Specification{
		Provides: provides,
		Requires: requires,
	}
}

func isSupportedKey(key string) bool {
	// '(' indicates the start of a boolean expression, which is not supported in syft at this time.
	// See https://rpm-software-management.github.io/rpm/manual/boolean_dependencies.html for more details
	//
	// examples:
	//  - (rpmlib(PayloadIsZstd) <= 5.4.18-1)
	//  - (glibc-gconv-extra(aarch-64) = 2.34-83.el9.12 if redhat-rpm-config)
	//  - (java-headless or java-17-headless or java-11-headless or java-1.8.0-headless)
	//  - (llvm if clang)
	//  - (pyproject-rpm-macros = 1.9.0-1.el9 if pyproject-rpm-macros)
	//  - (gcc >= 11 with gcc < 12)

	return !strings.HasPrefix(strings.TrimSpace(key), "(")
}
