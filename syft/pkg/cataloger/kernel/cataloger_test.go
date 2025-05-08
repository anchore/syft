package kernel

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_KernelCataloger(t *testing.T) {
	kernelPkg := pkg.Package{
		Name:    "linux-kernel",
		Version: "6.0.7-301.fc37.x86_64",
		FoundBy: "linux-kernel-cataloger",
		Locations: file.NewLocationSet(
			file.NewVirtualLocation(
				"/lib/modules/6.0.7-301.fc37.x86_64/vmlinuz",
				"/lib/modules/6.0.7-301.fc37.x86_64/vmlinuz",
			),
		),
		Type: pkg.LinuxKernelPkg,
		PURL: "pkg:generic/linux-kernel@6.0.7-301.fc37.x86_64",
		CPEs: []cpe.CPE{cpe.Must("cpe:2.3:o:linux:linux_kernel:6.0.7-301.fc37.x86_64:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource)},
		Metadata: pkg.LinuxKernel{
			Name:            "",
			Architecture:    "x86",
			Version:         "6.0.7-301.fc37.x86_64",
			ExtendedVersion: "6.0.7-301.fc37.x86_64 (mockbuild@bkernel01.iad2.fedoraproject.org) #1 SMP PREEMPT_DYNAMIC Fri Nov 4 18:35:48 UTC 2022",
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
		Name:    "ttynull",
		Version: "",
		FoundBy: "linux-kernel-cataloger",
		Locations: file.NewLocationSet(
			file.NewVirtualLocation("/lib/modules/6.0.7-301.fc37.x86_64/kernel/drivers/tty/ttynull.ko",
				"/lib/modules/6.0.7-301.fc37.x86_64/kernel/drivers/tty/ttynull.ko",
			),
		),
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseFromLocations("GPL v2",
				file.NewVirtualLocation(
					"/lib/modules/6.0.7-301.fc37.x86_64/kernel/drivers/tty/ttynull.ko",
					"/lib/modules/6.0.7-301.fc37.x86_64/kernel/drivers/tty/ttynull.ko",
				),
			),
		),
		Type: pkg.LinuxKernelModulePkg,
		PURL: "pkg:generic/ttynull",
		Metadata: pkg.LinuxKernelModule{
			Name:          "ttynull",
			Version:       "",
			SourceVersion: "",
			License:       "GPL v2",
			Path:          "/lib/modules/6.0.7-301.fc37.x86_64/kernel/drivers/tty/ttynull.ko",
			Description:   "",
			KernelVersion: "6.0.7-301.fc37.x86_64",
			VersionMagic:  "6.0.7-301.fc37.x86_64 SMP preempt mod_unload ",
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
				LinuxKernelCatalogerConfig{
					CatalogModules: true,
				},
			),
		)
}
