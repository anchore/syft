package binary

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_ELF_Package_Cataloger(t *testing.T) {
	expectedPkgs := []pkg.Package{
		{
			Name:    "libhello_world.so",
			Version: "0.01",
			PURL:    "pkg:generic/syftsys/libhello_world.so@0.01",
			FoundBy: "",
			Locations: file.NewLocationSet(file.NewVirtualLocation("/usr/local/bin/elftests/elfbinwithnestedlib/bin/lib/libhello_world.so", "/usr/local/bin/elftests/elfbinwithnestedlib/bin/lib/libhello_world.so"),
				file.NewVirtualLocation("/usr/local/bin/elftests/elfbinwithsisterlib/lib/libhello_world.so", "/usr/local/bin/elftests/elfbinwithsisterlib/lib/libhello_world.so"),
				file.NewVirtualLocation("/usr/local/bin/elftests/elfbinwithsisterlib/lib/libhello_world2.so", "/usr/local/bin/elftests/elfbinwithsisterlib/lib/libhello_world2.so"),
			),
			Language: "",
			Type:     pkg.BinaryPkg,
			Metadata: pkg.ELFBinaryPackageNotes{
				Type:   "testfixture",
				Vendor: "syft",
				System: "syftsys",
				Source: "",
				Commit: "",
			},
		},
		{
			Name:    "syfttestfixture",
			Version: "0.01",
			PURL:    "pkg:generic/syftsys/syfttestfixture@0.01",
			FoundBy: "",
			Locations: file.NewLocationSet(file.NewLocation("/usr/local/bin/elftests/elfbinwithnestedlib/bin/elfbinwithnestedlib").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
				file.NewLocation("/usr/local/bin/elftests/elfbinwithsisterlib/bin/elfwithparallellibbin1").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
				file.NewLocation("/usr/local/bin/elftests/elfbinwithsisterlib/bin/elfwithparallellibbin2").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
			Language: "",
			Type:     pkg.BinaryPkg,
			Metadata: pkg.ELFBinaryPackageNotes{
				Type:   "testfixture",
				Vendor: "syft",
				System: "syftsys",
				Source: "",
				Commit: "",
			},
		},
	}

	pkgtest.NewCatalogTester().
		WithImageResolver(t, "elf-test-fixtures").
		IgnoreLocationLayer(). // this fixture can be rebuilt, thus the layer ID will change
		Expects(expectedPkgs, nil).
		TestCataloger(t, NewELFPackageCataloger())

	// expectedPkgs = []pkg.Package{
	// 	{
	// 		Name:      "libhello_world.so",
	// 		Version:   "0.01",
	// 		PURL:      "pkg:generic/syftsys/libhello_world.so@0.01",
	// 		FoundBy:   "",
	// 		Locations: file.NewLocationSet(file.NewVirtualLocation("/usr/local/bin/syftelftest/lib/libhello_world.so", "/usr/local/bin/syftelftest/lib/libhello_world.so")),
	// 		Language:  "",
	// 		Type:      pkg.BinaryPkg,
	// 		Metadata: pkg.ELFBinaryPackageNotes{
	// 			Type:   "testfixture",
	// 			Vendor: "syft",
	// 			System: "syftsys",
	// 		},
	// 	},
	// 	{
	// 		Name:      "syfttestfixture",
	// 		Version:   "0.01",
	// 		PURL:      "pkg:generic/syftsys/syfttestfixture@0.01",
	// 		FoundBy:   "",
	// 		Locations: file.NewLocationSet(file.NewVirtualLocation("/usr/local/bin/syftelftest/bin/elfwithparallellibbin1", "/usr/local/bin/syftelftest/bin/elfwithparallellibbin1")),
	// 		Language:  "",
	// 		Type:      pkg.BinaryPkg,
	// 		Metadata: pkg.ELFBinaryPackageNotes{
	// 			Type:   "testfixture",
	// 			Vendor: "syft",
	// 			System: "syftsys",
	// 		},
	// 	},
	// 	{
	// 		Name:      "libhello_world2.so",
	// 		Version:   "0.01",
	// 		PURL:      "pkg:generic/syftsys/libhello_world2.so@0.01",
	// 		FoundBy:   "",
	// 		Locations: file.NewLocationSet(file.NewVirtualLocation("/usr/local/bin/syftelftest/lib/libhello_world2.so", "/usr/local/bin/syftelftest/lib/libhello_world2.so")),
	// 		Language:  "",
	// 		Type:      pkg.BinaryPkg,
	// 		Metadata: pkg.ELFBinaryPackageNotes{
	// 			Type:   "testfixture",
	// 			Vendor: "syft",
	// 			System: "syftsys",
	// 		},
	// 	},

	// 	{
	// 		Name:      "syfttestfixture",
	// 		Version:   "0.01",
	// 		PURL:      "pkg:generic/syftsys/syfttestfixture@0.01",
	// 		FoundBy:   "",
	// 		Locations: file.NewLocationSet(file.NewVirtualLocation("/usr/local/bin/syftelftest/bin/elfwithparallellibbin2", "/usr/local/bin/syftelftest/bin/elfwithparallellibbin2")),
	// 		Language:  "",
	// 		Type:      pkg.BinaryPkg,
	// 		Metadata: pkg.ELFBinaryPackageNotes{
	// 			Type:   "testfixture",
	// 			Vendor: "syft",
	// 			System: "syftsys",
	// 		},
	// 	},
	// }
	// pkgtest.NewCatalogTester().
	// 	WithImageResolver(t, "elf-test-fixture-sister-lib").
	// 	IgnoreLocationLayer(). // this fixture can be rebuilt, thus the layer ID will change
	// 	Expects(expectedPkgs, nil).
	// 	TestCataloger(t, NewELFPackageCataloger())

}
