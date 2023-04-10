/*
Package kernel provides a concrete Cataloger implementation for linux kernel and module files.
*/
package kernel

import (
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/source"
)

var _ pkg.Cataloger = (*LinuxKernelCataloger)(nil)

type LinuxCatalogerConfig struct {
	KernelArchiveGlobAppends []string
	KernelModuleGlobAppends  []string
	CatalogModules           bool
}

type LinuxKernelCataloger struct {
	cfg LinuxCatalogerConfig
}

func DefaultLinuxCatalogerConfig() LinuxCatalogerConfig {
	return LinuxCatalogerConfig{
		KernelArchiveGlobAppends: []string{},
		KernelModuleGlobAppends:  []string{},
		CatalogModules:           true,
	}
}

var kernelArchiveGlobs = []string{
	"kernel",
	"kernel-*",
	"vmlinux",
	"vmlinux-*",
	"vmlinuz",
	"vmlinuz-*",
}

var kernelModuleGlobs = []string{
	"**/lib/modules/**/*.ko",
}

// NewLinuxKernelCataloger returns a new kernel files cataloger object.
func NewLinuxKernelCataloger(cfg LinuxCatalogerConfig) *LinuxKernelCataloger {
	return &LinuxKernelCataloger{
		cfg: cfg,
	}
}

func (l LinuxKernelCataloger) Name() string {
	return "linux-kernel-cataloger"
}

func (l LinuxKernelCataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
	var combinedKernelGlobs []string
	for _, g := range kernelArchiveGlobs {
		combinedKernelGlobs = append(combinedKernelGlobs, "**/"+g)
	}
	for _, g := range l.cfg.KernelArchiveGlobAppends {
		combinedKernelGlobs = append(combinedKernelGlobs, "**/"+g)
	}
	kernelPackages, kernelRelationships, err := generic.NewCataloger(l.Name()).WithParserByGlobs(parseLinuxKernelFile, combinedKernelGlobs...).Catalog(resolver)
	if err != nil {
		// TODO: don't bail. Try to return what we have instead and log a warning.
		return nil, nil, err
	}

	var combinedModuleGlobs []string
	for _, g := range kernelModuleGlobs {
		combinedModuleGlobs = append(combinedModuleGlobs, "**/"+g)
	}
	for _, g := range l.cfg.KernelArchiveGlobAppends {
		combinedModuleGlobs = append(combinedModuleGlobs, "**/"+g)
	}
	modulePackages, moduleRelationships, err := generic.NewCataloger(l.Name()).WithParserByGlobs(parseLinuxKernelModuleFile, combinedModuleGlobs...).Catalog(resolver)
	if err != nil {
		// TODO: don't bail. Try to return what we have instead and log a warning.
		return nil, nil, err
	}

	moduleToKernelRelationships := createKernelToModuleRelationships(kernelPackages, modulePackages)

	var allPackages []pkg.Package
	allPackages = append(allPackages, kernelPackages...)
	allPackages = append(allPackages, modulePackages...)

	var allRelationships []artifact.Relationship
	allRelationships = append(allRelationships, kernelRelationships...)
	allRelationships = append(allRelationships, moduleRelationships...)
	allRelationships = append(allRelationships, moduleToKernelRelationships...)

	return allPackages, allRelationships, nil
}

func createKernelToModuleRelationships(kernelPackages, modulePackages []pkg.Package) []artifact.Relationship {
	// organize kernel and module packages by kernel version
	kernelPackagesByVersion := make(map[string][]*pkg.Package)
	for idx, p := range kernelPackages {
		kernelPackagesByVersion[p.Version] = append(kernelPackagesByVersion[p.Version], &kernelPackages[idx])
	}

	modulesByKernelVersion := make(map[string][]*pkg.Package)
	for idx, p := range modulePackages {
		m, ok := p.Metadata.(pkg.LinuxKernelModuleMetadata)
		if !ok {
			// TODO: warning?
			continue
		}
		modulesByKernelVersion[m.KernelVersion] = append(modulesByKernelVersion[m.KernelVersion], &modulePackages[idx])
	}

	// create relationships between kernel and modules: [module] --(depends on)--> [kernel]
	// since we try to use singular directions for relationships, we'll use "dependency of" here instead:
	// [kernel] --(dependency of)--> [module]
	var moduleToKernelRelationships []artifact.Relationship
	for kernelVersion, modules := range modulesByKernelVersion {
		kps, ok := kernelPackagesByVersion[kernelVersion]
		if !ok {
			// it's ok if there is a module that has no installed kernel...
			continue
		}

		// we don't know which kernel is the "right" one, so we'll create a relationship for each one
		for _, kp := range kps {
			for _, mp := range modules {
				moduleToKernelRelationships = append(moduleToKernelRelationships, artifact.Relationship{
					From: kp,
					To:   mp,
					Type: artifact.DependencyOfRelationship,
				})
			}
		}
	}

	return moduleToKernelRelationships
}
