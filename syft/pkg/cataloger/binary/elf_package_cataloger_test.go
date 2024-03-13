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
			Locations: file.NewLocationSet(
				file.NewVirtualLocation("/usr/local/bin/elftests/elfbinwithnestedlib/bin/lib/libhello_world.so", "/usr/local/bin/elftests/elfbinwithnestedlib/bin/lib/libhello_world.so"),
				file.NewVirtualLocation("/usr/local/bin/elftests/elfbinwithsisterlib/lib/libhello_world.so", "/usr/local/bin/elftests/elfbinwithsisterlib/lib/libhello_world.so"),
				file.NewVirtualLocation("/usr/local/bin/elftests/elfbinwithsisterlib/lib/libhello_world2.so", "/usr/local/bin/elftests/elfbinwithsisterlib/lib/libhello_world2.so"),
			),
			Language: "",
			Type:     pkg.BinaryPkg,
			Metadata: pkg.ELFBinaryPackageNoteJSONPayload{
				Type:       "testfixture",
				Vendor:     "syft",
				System:     "syftsys",
				SourceRepo: "https://github.com/someone/somewhere.git",
				Commit:     "5534c38d0ffef9a3f83154f0b7a7fb6ab0ab6dbb",
			},
		},
		{
			Name:    "syfttestfixture",
			Version: "0.01",
			PURL:    "pkg:generic/syftsys/syfttestfixture@0.01",
			FoundBy: "",
			Locations: file.NewLocationSet(
				file.NewLocation("/usr/local/bin/elftests/elfbinwithnestedlib/bin/elfbinwithnestedlib").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
				file.NewLocation("/usr/local/bin/elftests/elfbinwithsisterlib/bin/elfwithparallellibbin1").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
				file.NewLocation("/usr/local/bin/elftests/elfbinwithsisterlib/bin/elfwithparallellibbin2").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
			Language: "",
			Type:     pkg.BinaryPkg,
			Metadata: pkg.ELFBinaryPackageNoteJSONPayload{
				Type:       "testfixture",
				Vendor:     "syft",
				System:     "syftsys",
				SourceRepo: "https://github.com/someone/somewhere.git",
				Commit:     "5534c38d0ffef9a3f83154f0b7a7fb6ab0ab6dbb",
			},
		},
	}

	pkgtest.NewCatalogTester().
		WithImageResolver(t, "elf-test-fixtures").
		IgnoreLocationLayer(). // this fixture can be rebuilt, thus the layer ID will change
		Expects(expectedPkgs, nil).
		TestCataloger(t, NewELFPackageCataloger())

}
