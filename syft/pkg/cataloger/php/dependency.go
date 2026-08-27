package php

import (
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

func composerDependencySpecifier(p pkg.Package) dependency.Specification {
	name, metaProvides, metaRequires, ok := composerMetadataExtractor(p)
	if !ok {
		log.Tracef("cataloger failed to extract composer lock metadata for package %+v", p.Name)
		return dependency.Specification{}
	}

	// the package name is always provided by the package itself
	provides := []string{name}

	for name := range metaProvides {
		provides = append(provides, name)
	}

	var requires []string

	for name := range metaRequires {
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
func composerMetadataExtractor(p pkg.Package) (string, map[string]string, map[string]string, bool) {
	switch meta := p.Metadata.(type) {
	case pkg.PhpComposerLockEntry:
		return meta.Name, meta.Provide, meta.Require, true
	case pkg.PhpComposerInstalledEntry:
		return meta.Name, meta.Provide, meta.Require, true
	default:
		return "", nil, nil, false
	}
}
