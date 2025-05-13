/*
Package kernel provides a concrete Cataloger implementation for linux kernel and module files.
*/
package kernel

import (
	"context"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ pkg.Cataloger = (*linuxKernelCataloger)(nil)

type LinuxKernelCatalogerConfig struct {
	CatalogModules bool `yaml:"catalog-modules" json:"catalog-modules" mapstructure:"catalog-modules"`
}

type linuxKernelCataloger struct {
	cfg LinuxKernelCatalogerConfig
}

func DefaultLinuxKernelCatalogerConfig() LinuxKernelCatalogerConfig {
	return LinuxKernelCatalogerConfig{
		CatalogModules: true,
	}
}

var kernelArchiveGlobs = []string{
	"**/kernel",
	"**/kernel-*",
	"**/vmlinux",
	"**/vmlinux-*",
	"**/vmlinuz",
	"**/vmlinuz-*",
}

var kernelModuleGlobs = []string{
	"**/lib/modules/**/*.ko",
}

// NewLinuxKernelCataloger returns a new kernel files cataloger object.
func NewLinuxKernelCataloger(cfg LinuxKernelCatalogerConfig) pkg.Cataloger {
	return &linuxKernelCataloger{
		cfg: cfg,
	}
}

func (l linuxKernelCataloger) Name() string {
	return "linux-kernel-cataloger"
}

func (l linuxKernelCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	var allPackages []pkg.Package
	var allRelationships []artifact.Relationship
	var errs error

	kernelPackages, kernelRelationships, err := generic.NewCataloger(l.Name()).WithParserByGlobs(parseLinuxKernelFile, kernelArchiveGlobs...).Catalog(ctx, resolver)
	if err != nil {
		errs = unknown.Join(errs, err)
	}

	allRelationships = append(allRelationships, kernelRelationships...)
	allPackages = append(allPackages, kernelPackages...)

	if l.cfg.CatalogModules {
		modulePackages, moduleRelationships, err := generic.NewCataloger(l.Name()).WithParserByGlobs(parseLinuxKernelModuleFile, kernelModuleGlobs...).Catalog(ctx, resolver)
		if err != nil {
			errs = unknown.Join(errs, err)
		}

		allPackages = append(allPackages, modulePackages...)

		moduleToKernelRelationships := createKernelToModuleRelationships(kernelPackages, modulePackages)
		allRelationships = append(allRelationships, moduleRelationships...)
		allRelationships = append(allRelationships, moduleToKernelRelationships...)
	}

	return allPackages, allRelationships, errs
}

func createKernelToModuleRelationships(kernelPackages, modulePackages []pkg.Package) []artifact.Relationship {
	// organize kernel and module packages by kernel version
	kernelPackagesByVersion := make(map[string][]*pkg.Package)
	for idx, p := range kernelPackages {
		kernelPackagesByVersion[p.Version] = append(kernelPackagesByVersion[p.Version], &kernelPackages[idx])
	}

	modulesByKernelVersion := make(map[string][]*pkg.Package)
	for idx, p := range modulePackages {
		m, ok := p.Metadata.(pkg.LinuxKernelModule)
		if !ok {
			log.Debugf("linux-kernel-module package found without metadata: %s@%s", p.Name, p.Version)
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
					// note: relationships should have Package objects, not pointers
					From: *kp,
					To:   *mp,
					Type: artifact.DependencyOfRelationship,
				})
			}
		}
	}

	return moduleToKernelRelationships
}
