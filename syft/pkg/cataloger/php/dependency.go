package php

import (
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

type ComposerPackageLinks struct {
	Name     string
	Provides map[string]string
	Requires map[string]string
	Replace  map[string]string
}

func composerDependencySpecifier(p pkg.Package) dependency.Specification {
	packageLinks, ok := composerMetadataExtractor(p)
	if !ok {
		log.Tracef("cataloger failed to extract composer lock metadata for package %+v", p.Name)
		return dependency.Specification{}
	}

	// the package name is always provided by the package itself
	provides := []string{packageLinks.Name}

	for name := range packageLinks.Provides {
		provides = append(provides, name)
	}

	for name := range packageLinks.Replace {
		provides = append(provides, name)
	}

	var requires []string

	for name := range packageLinks.Requires {
		requires = append(requires, name)
	}

	return dependency.Specification{
		ProvidesRequires: dependency.ProvidesRequires{
			Provides: provides,
			Requires: requires,
		},
	}
}

// Get metadata type independent information from a package
func composerMetadataExtractor(p pkg.Package) (ComposerPackageLinks, bool) {
	switch meta := p.Metadata.(type) {
	case pkg.PhpComposerLockEntry:
		return ComposerPackageLinks{
			Name:     meta.Name,
			Provides: meta.Provide,
			Requires: meta.Require,
			Replace:  meta.Replace,
		}, true
	case pkg.PhpComposerInstalledEntry:
		return ComposerPackageLinks{
			Name:     meta.Name,
			Provides: meta.Provide,
			Requires: meta.Require,
			Replace:  meta.Replace,
		}, true
	default:
		return ComposerPackageLinks{}, false
	}
}
