package kernel

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
)

func Test_JavascriptCataloger(t *testing.T) {
	kernelPkg := pkg.Package{
		Name:    "linux-kernel",
		Version: "6.2.9-200.fc37.x86_64",
		FoundBy: "linux-kernel-cataloger",
		Locations: source.NewLocationSet(
			source.NewVirtualLocation(
				"/lib/modules/6.2.9-200.fc37.x86_64/vmlinuz",
				"/lib/modules/6.2.9-200.fc37.x86_64/vmlinuz",
			),
		),
		Type:         pkg.LinuxKernelPkg,
		PURL:         "pkg:generic/linux-kernel@6.2.9-200.fc37.x86_64",
		MetadataType: pkg.LinuxKernelMetadataType,
		Metadata: pkg.LinuxKernelMetadata{
			Name:            "",
			Architecture:    "x86",
			Version:         "6.2.9-200.fc37.x86_64",
			ExtendedVersion: "6.2.9-200.fc37.x86_64 (mockbuild@bkernel02.iad2.fedoraproject.org) #1 SMP PREEMPT_DYNAMIC Thu Mar 30 22:31:57 UTC 2023",
			BuildTime:       "",
			Author:          "",
			Format:          "bzImage",
			RWRootFS:        false,
			SwapDevice:      0,
			RootDevice:      0,
			VideoMode:       "Video mode 65535",
		},
	}

	kernelModulePkg := pkg.Package{
		Name:    "fsa4480",
		Version: "",
		FoundBy: "linux-kernel-cataloger",
		Locations: source.NewLocationSet(
			source.NewVirtualLocation("/lib/modules/6.2.9-200.fc37.x86_64/kernel/drivers/usb/typec/mux/fsa4480.ko",
				"/lib/modules/6.2.9-200.fc37.x86_64/kernel/drivers/usb/typec/mux/fsa4480.ko",
			),
		),
		Licenses: []string{
			"GPL v2",
		},
		Type:         pkg.LinuxKernelModulePkg,
		PURL:         "pkg:generic/fsa4480",
		MetadataType: pkg.LinuxKernelModuleMetadataType,
		Metadata: pkg.LinuxKernelModuleMetadata{
			Name:          "fsa4480",
			Version:       "",
			SourceVersion: "",
			License:       "GPL v2",
			Path:          "/lib/modules/6.2.9-200.fc37.x86_64/kernel/drivers/usb/typec/mux/fsa4480.ko",
			Description:   "ON Semiconductor FSA4480 driver",
			KernelVersion: "6.2.9-200.fc37.x86_64",
			VersionMagic:  "6.2.9-200.fc37.x86_64 SMP preempt mod_unload ",
			Parameters:    map[string]pkg.LinuxKernelModuleParameter{},
		},
	}

	expectedPkgs := []pkg.Package{
		kernelPkg,
		kernelModulePkg,
	}
	expectedRelationships := []artifact.Relationship{
		{
			From: kernelPkg,
			To:   kernelModulePkg,
			Type: artifact.DependencyOfRelationship,
		},
	}

	pkgtest.NewCatalogTester().
		WithImageResolver(t, "image-kernel-and-modules").
		IgnoreLocationLayer().
		Expects(expectedPkgs, expectedRelationships).
		TestCataloger(t,
			NewLinuxKernelCataloger(
				LinuxCatalogerConfig{
					CatalogModules: true,
				},
			),
		)
}
